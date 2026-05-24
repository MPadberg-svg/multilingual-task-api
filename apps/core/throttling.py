"""Custom DRF throttling classes for health and AI-assist endpoints."""

from __future__ import annotations

import logging
from typing import Any

from rest_framework.throttling import AnonRateThrottle, SimpleRateThrottle

logger = logging.getLogger(__name__)


class HealthCheckAnonRateThrottle(AnonRateThrottle):
    """Throttle anonymous traffic only for the health-check endpoint."""

    scope = "anon"

    def get_cache_key(self, request: Any, view: Any) -> str | None:
        path = request.path.lower()
        if "/health/" not in path:
            return None
        return super().get_cache_key(request, view)


class _BaseAIAssistThrottle(SimpleRateThrottle):
    """Shared behavior for AI-assist per-user throttles."""

    cache_format = "mltask:throttle:%(scope)s:%(ident)s"

    def get_cache_key(self, request: Any, view: Any) -> str | None:
        user = getattr(request, "user", None)
        if not user or not getattr(user, "is_authenticated", False):
            return None
        user_id = getattr(user, "pk", None)
        if user_id is None:
            return None
        return self.cache_format % {"scope": self.scope, "ident": user_id}

    def allow_request(self, request: Any, view: Any) -> bool:
        allowed = super().allow_request(request, view)
        if not allowed:
            self._log_violation(request)
        return allowed

    def _log_violation(self, request: Any) -> None:
        user = getattr(request, "user", None)
        logger.warning(
            "Throttle exceeded",
            extra={
                "scope": self.scope,
                "user_id": str(getattr(user, "pk", "anonymous")),
                "path": getattr(request, "path", ""),
            },
        )

    def wait(self) -> float | None:
        if not self.history:
            return None
        return max(self.duration - (self.now - self.history[-1]), 0.0)


class AIAssistRateThrottle(_BaseAIAssistThrottle):
    """Sustained AI-assist quota (configured as 20/hour)."""

    scope = "ai_assist"


class BurstRateThrottle(_BaseAIAssistThrottle):
    """Burst AI-assist quota (configured as 5/min)."""

    scope = "ai_assist_burst"
