"""Custom DRF throttling for AI assist + health endpoints.

Defines three throttles:

* ``AIAssistRateThrottle`` — sustained per-user limit (20/hour).
* ``BurstRateThrottle``     — short-window burst limit (5/minute).
* ``HealthCheckAnonRateThrottle`` — generous anon limit for liveness/health probes.

All AI throttles are per-authenticated-user (anonymous requests get a
``None`` cache key, which DRF treats as "do not throttle this scope but
block in the view via ``IsAuthenticated``").

Cache keys use the project prefix ``mltask:throttle:<scope>:<user-pk>``
so they sit alongside the rest of the app's cache traffic and can be
invalidated as a group.
"""

from __future__ import annotations

import logging
from typing import Any

from rest_framework.throttling import AnonRateThrottle, SimpleRateThrottle

logger = logging.getLogger(__name__)


class _UserScopedThrottle(SimpleRateThrottle):
    """Base class for per-authenticated-user throttles.

    Subclasses must set ``scope`` (matches a key in
    ``REST_FRAMEWORK['DEFAULT_THROTTLE_RATES']``).
    """

    cache_format = "mltask:throttle:%(scope)s:%(ident)s"

    def get_cache_key(self, request: Any, view: Any) -> str | None:
        user = getattr(request, "user", None)
        if user is None or not getattr(user, "is_authenticated", False):
            return None
        return self.cache_format % {"scope": self.scope, "ident": user.pk}

    def throttle_failure(self) -> bool:
        self._log_violation()
        return super().throttle_failure()

    def wait(self) -> float | None:
        """Seconds until the oldest in-window request expires.

        Overrides DRF's default, which returns a smoothed estimate that
        is non-``None`` even when no requests have been seen. Tests rely
        on ``None`` meaning "not currently throttling".
        """
        history = getattr(self, "history", None) or []
        if not history:
            return None
        return self.duration - (self.now - history[-1])

    def _log_violation(self) -> None:
        """Emit a structured warning when a request is rate-limited.

        Kept as a separate method so tests can patch it without
        intercepting the entire logging stack.
        """
        logger.warning(
            "throttle.violation",
            extra={
                "scope": self.scope,
                "rate": getattr(self, "rate", None),
                "history_size": len(getattr(self, "history", []) or []),
            },
        )


class AIAssistRateThrottle(_UserScopedThrottle):
    """Sustained AI-assist rate limit (default 20/hour, per authenticated user)."""

    scope = "ai_assist"


class BurstRateThrottle(_UserScopedThrottle):
    """Short-window burst limit (default 5/minute, per authenticated user)."""

    scope = "ai_assist_burst"


class HealthCheckAnonRateThrottle(AnonRateThrottle):
    """Dedicated high-headroom throttle for orchestrator health/metrics probes.

    Uses the ``health`` rate scope (default ``600/min``) so Docker, ECS, and
    ALB health checks never exhaust the stricter ``anon`` (``100/day``) budget.
    Fails open if the cache backend is unreachable so liveness/readiness probes
    never crash with HTTP 500 during a cache outage.
    """

    scope = "health"

    def allow_request(self, request: Any, view: Any) -> bool:
        try:
            if self.rate is None:
                return True
            self.key = self.get_cache_key(request, view)
            if self.key is None:
                return True
            history = self.cache.get(self.key, [])
            if not isinstance(history, list):
                return True
            self.history = history
            self.now = self.timer()
            while self.history and self.history[-1] <= self.now - self.duration:
                self.history.pop()
            if len(self.history) >= self.num_requests:
                return self.throttle_failure()
            return self.throttle_success()
        except Exception:
            logger.debug(
                "HealthCheckAnonRateThrottle failing open due to cache error", exc_info=True
            )
            return True
