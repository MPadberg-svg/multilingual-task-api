"""
Circuit breaker for OpenAI API calls.
Prevents cascade failures when OpenAI is unavailable.

States:
    CLOSED    — Normal. Requests pass through.
    OPEN      — Too many failures. Requests fail immediately.
    HALF_OPEN — Recovery test. One request allowed.
"""

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
    """Raised when circuit is OPEN and request is blocked."""

    pass


class CircuitBreaker:
    """Thread-safe circuit breaker with configurable thresholds."""

    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
    ):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time: float | None = None
        self._lock = threading.Lock()

    @property
    def state(self) -> CircuitState:
        with self._lock:
            if (
                self._state == CircuitState.OPEN
                and self._last_failure_time
                and (time.monotonic() - self._last_failure_time) >= self.recovery_timeout
            ):
                logger.info("Circuit '%s' entering HALF_OPEN state", self.name)
                self._state = CircuitState.HALF_OPEN
            return self._state

    def call(self, func: Callable, *args: Any, **kwargs: Any) -> Any:
        """Execute func through the circuit breaker."""
        if self.state == CircuitState.OPEN:
            raise CircuitOpenError(
                f"Circuit '{self.name}' is OPEN. " f"Retry in {self.recovery_timeout}s."
            )
        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except Exception as e:
            self._on_failure()
            raise e

    def _on_success(self) -> None:
        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                logger.info("Circuit '%s' recovered — state: CLOSED", self.name)
            self._failure_count = 0
            self._state = CircuitState.CLOSED

    def _on_failure(self) -> None:
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.monotonic()
            if self._failure_count >= self.failure_threshold:
                if self._state != CircuitState.OPEN:
                    logger.warning(
                        "Circuit '%s' OPENED after %d failures",
                        self.name,
                        self._failure_count,
                    )
                self._state = CircuitState.OPEN

    def get_status(self) -> dict:
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
