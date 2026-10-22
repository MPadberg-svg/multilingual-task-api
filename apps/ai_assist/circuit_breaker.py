"""Circuit breaker for OpenAI API calls (in-memory + optional cluster-wide Redis coordination).

Prevents cascade failures when OpenAI is unavailable and enforces a strict
single-flight recovery probe in ``HALF_OPEN`` state across threads and
(when ``shared_cache=True``) across Gunicorn/Celery worker processes via Redis.

States:
    CLOSED    — Normal. Requests pass through.
    OPEN      — Too many failures. Requests fail immediately.
    HALF_OPEN — Recovery test. Strictly one probe request allowed at a time.
"""

from __future__ import annotations

import logging
import threading
import time
from enum import Enum
from typing import Any, Callable

from django.core.cache import cache

logger = logging.getLogger(__name__)


class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitOpenError(Exception):
    """Raised when circuit is OPEN (or HALF_OPEN probe is busy) and request is blocked."""


class CircuitBreaker:
    """Thread-safe and optionally Redis-coordinated single-flight circuit breaker."""

    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
        shared_cache: bool = False,
    ) -> None:
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.shared_cache = shared_cache

        self._fail_key = f"mltask:cb:{name}:failures"
        self._open_until_key = f"mltask:cb:{name}:open_until"
        self._probe_lock_key = f"mltask:cb:{name}:probe_lock"

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time: float | None = None
        self._half_open_probe_in_flight = False
        self._lock = threading.Lock()

    def _state_ttl(self) -> int:
        return max(60, self.recovery_timeout * 4)

    def _shared_state(self) -> CircuitState | None:
        """Read cluster-wide state from Django cache/Redis, returning None on backend error."""
        if not self.shared_cache:
            return None
        try:
            raw_open_until = cache.get(self._open_until_key)
            if raw_open_until is None:
                return CircuitState.CLOSED
            open_until = float(raw_open_until)
            if time.time() < open_until:
                return CircuitState.OPEN
            return CircuitState.HALF_OPEN
        except Exception:
            logger.debug("Shared cache unavailable for circuit '%s'; using local state", self.name)
            return None

    def _refresh_state_unlocked(self) -> CircuitState:
        if (
            self._state == CircuitState.OPEN
            and self._last_failure_time is not None
            and (time.monotonic() - self._last_failure_time) >= self.recovery_timeout
        ):
            logger.info("Circuit '%s' entering HALF_OPEN state", self.name)
            self._state = CircuitState.HALF_OPEN
            self._half_open_probe_in_flight = False
        return self._state

    @property
    def state(self) -> CircuitState:
        shared = self._shared_state()
        if shared is not None:
            return shared
        with self._lock:
            return self._refresh_state_unlocked()

    def _incr_shared_failures(self) -> int | None:
        ttl = self._state_ttl()
        try:
            return int(cache.incr(self._fail_key, 1))
        except ValueError:
            try:
                if cache.add(self._fail_key, 1, timeout=ttl):
                    return 1
                return int(cache.incr(self._fail_key, 1))
            except Exception:
                return None
        except Exception:
            return None

    def call(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Execute ``func`` through the circuit breaker."""
        shared = self._shared_state()
        used_shared = shared is not None
        was_half_open = False

        if used_shared:
            if shared == CircuitState.OPEN:
                raise CircuitOpenError(
                    f"Circuit '{self.name}' is OPEN. Retry in {self.recovery_timeout}s."
                )
            if shared == CircuitState.HALF_OPEN:
                was_half_open = True
                try:
                    acquired = cache.add(
                        self._probe_lock_key,
                        "1",
                        timeout=max(5, self.recovery_timeout),
                    )
                except Exception:
                    acquired = True
                if not acquired:
                    raise CircuitOpenError(
                        f"Circuit '{self.name}' recovery probe already in progress."
                    )
        else:
            with self._lock:
                current = self._refresh_state_unlocked()
                if current == CircuitState.OPEN:
                    raise CircuitOpenError(
                        f"Circuit '{self.name}' is OPEN. Retry in {self.recovery_timeout}s."
                    )
                if current == CircuitState.HALF_OPEN:
                    if self._half_open_probe_in_flight:
                        raise CircuitOpenError(
                            f"Circuit '{self.name}' recovery probe already in progress."
                        )
                    self._half_open_probe_in_flight = True
                    was_half_open = True

        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except Exception:
            self._on_failure(was_half_open=was_half_open)
            raise

    def _on_success(self) -> None:
        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                logger.info("Circuit '%s' recovered — state: CLOSED", self.name)
            self._failure_count = 0
            self._half_open_probe_in_flight = False
            self._state = CircuitState.CLOSED

        if self.shared_cache:
            try:
                cache.delete_many([self._fail_key, self._open_until_key, self._probe_lock_key])
            except Exception:
                logger.debug("Unable to clear shared circuit keys for '%s'", self.name)

    def _on_failure(self, *, was_half_open: bool = False) -> None:
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.monotonic()
            self._half_open_probe_in_flight = False
            if (
                was_half_open
                or self._state == CircuitState.HALF_OPEN
                or self._failure_count >= self.failure_threshold
            ):
                if self._state != CircuitState.OPEN:
                    logger.warning(
                        "Circuit '%s' OPENED after %d failures",
                        self.name,
                        self._failure_count,
                    )
                self._state = CircuitState.OPEN

        if self.shared_cache:
            try:
                cache.delete(self._probe_lock_key)
                shared_count = self._incr_shared_failures()
                if was_half_open or (
                    shared_count is not None and shared_count >= self.failure_threshold
                ):
                    open_until = time.time() + self.recovery_timeout
                    cache.set(self._open_until_key, str(open_until), timeout=self._state_ttl())
            except Exception:
                logger.debug("Unable to persist shared circuit failure for '%s'", self.name)

    def reset(self) -> None:
        """Reset circuit breaker state (both in-memory and shared cache)."""
        with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._last_failure_time = None
            self._half_open_probe_in_flight = False

        if self.shared_cache:
            try:
                cache.delete_many([self._fail_key, self._open_until_key, self._probe_lock_key])
            except Exception:
                logger.debug("Unable to reset shared circuit keys for '%s'", self.name)

    def get_status(self) -> dict[str, Any]:
        failure_count = self._failure_count
        if self.shared_cache:
            try:
                cached_failures = cache.get(self._fail_key)
                if isinstance(cached_failures, int):
                    failure_count = cached_failures
            except Exception:
                logger.debug("Unable to read shared failure count for '%s'", self.name)
        return {
            "name": self.name,
            "state": self.state.value,
            "failure_count": failure_count,
            "failure_threshold": self.failure_threshold,
            "recovery_timeout_seconds": self.recovery_timeout,
            "shared_cache": self.shared_cache,
        }


# Singleton — cluster-coordinated via Django cache/Redis with thread-safe local fallback
openai_circuit_breaker = CircuitBreaker(
    name="openai",
    failure_threshold=5,
    recovery_timeout=60,
    shared_cache=True,
)
