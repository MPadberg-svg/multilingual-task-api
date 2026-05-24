"""Custom DRF throttling for AI assist + health endpoints.

Defines three throttles:

* ``AIAssistRateThrottle`` — sustained per-user limit (20/hour).
* ``BurstRateThrottle``     — short-window burst limit (5/minute).
* ``HealthCheckAnonRateThrottle`` — generous anon limit for liveness probes.

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
    """Generous anonymous limit for ``/health/`` and ``/metrics/`` style probes.

    Falls back to the global ``anon`` rate; a dedicated scope lets ops bump
    the limit for monitoring traffic without raising it everywhere.
    """

    scope = "anon"
