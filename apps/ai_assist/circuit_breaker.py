"""Circuit breaker for OpenAI API calls.

Prevents cascade failures when OpenAI is unavailable and enforces a strict
single-flight recovery probe in ``HALF_OPEN`` state.

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

logger = logging.getLogger(__name__)


class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitOpenError(Exception):
    """Raised when circuit is OPEN (or HALF_OPEN probe is busy) and request is blocked."""


class CircuitBreaker:
    """Thread-safe circuit breaker with single-flight half-open probing."""

    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
    ) -> None:
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time: float | None = None
        self._half_open_probe_in_flight = False
        self._lock = threading.Lock()

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
        with self._lock:
            return self._refresh_state_unlocked()

    def call(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Execute ``func`` through the circuit breaker."""
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

        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except Exception:
            self._on_failure()
            raise

    def _on_success(self) -> None:
        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                logger.info("Circuit '%s' recovered — state: CLOSED", self.name)
            self._failure_count = 0
            self._half_open_probe_in_flight = False
            self._state = CircuitState.CLOSED

    def _on_failure(self) -> None:
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.monotonic()
            self._half_open_probe_in_flight = False
            if self._state == CircuitState.HALF_OPEN or (
                self._failure_count >= self.failure_threshold
            ):
                if self._state != CircuitState.OPEN:
                    logger.warning(
                        "Circuit '%s' OPENED after %d failures",
                        self.name,
                        self._failure_count,
                    )
                self._state = CircuitState.OPEN

    def reset(self) -> None:
        """Reset circuit breaker state (useful for deterministic testing)."""
        with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._last_failure_time = None
            self._half_open_probe_in_flight = False

    def get_status(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "state": self.state.value,
            "failure_count": self._failure_count,
            "failure_threshold": self.failure_threshold,
            "recovery_timeout_seconds": self.recovery_timeout,
        }


# Singleton — import this everywhere
openai_circuit_breaker = CircuitBreaker(
    name="openai",
    failure_threshold=5,
    recovery_timeout=60,
)
