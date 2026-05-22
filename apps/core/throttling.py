"""Custom DRF throttling for AI assistance endpoints.

Provides sustained and burst rate limits for authenticated users only.
Anonymous users are explicitly blocked (return None from get_cache_key).
All throttle violations are logged at warning level for observability.
"""

from __future__ import annotations

import logging
from typing import Any

from rest_framework.request import Request
from rest_framework.throttling import AnonRateThrottle, SimpleRateThrottle
from rest_framework.views import View


logger: logging.Logger = logging.getLogger(__name__)

# Paths that should never be rate-limited (health probes, metrics)
HEALTH_PROBE_PATHS: set[str] = {
    "/api/v1/live/",
    "/api/v1/health/",
    "/api/v1/ready/",
    "/api/v1/metrics/",
}


class HealthCheckAnonRateThrottle(AnonRateThrottle):
    """Anonymous rate throttle that exempts health probe endpoints.

    Docker healthchecks hit /api/v1/live/ every 30s from 127.0.0.1.
    Without this exemption, AnonRateThrottle (100/day) blocks them.
    """

    def allow_request(self, request: Request, view: View) -> bool:
        """Skip throttling for health probe paths."""
        if request.path in HEALTH_PROBE_PATHS:
            return True
        return super().allow_request(request, view)


class AIAssistRateThrottle(SimpleRateThrottle):
    """Sustained rate limit for AI assistance: 20 requests per hour per user.

    Only applies to authenticated users. Anonymous requests are blocked
    by returning None from get_cache_key, which causes DRF to deny access.
    """

    scope: str = "ai_assist"
    rate: str = "20/hour"
    cache_format: str = "mltask:throttle:%(scope)s:%(ident)s"

    def get_cache_key(self, request: Request, view: View) -> str | None:
        """Generate per-user cache key. Returns None for anonymous users."""
        if not request.user or not request.user.is_authenticated:
            return None
        ident: str = str(request.user.pk)
        return self.cache_format % {"scope": self.scope, "ident": ident}

    def allow_request(self, request: Request, view: View) -> bool:
        """Check rate limit and log violations."""
        allowed: bool = super().allow_request(request, view)
        if not allowed:
            self._log_violation(request, "ai_assist")
        return allowed

    def wait(self) -> float | None:
        """Return seconds until the next request is allowed.

        Calculates based on the oldest request in the throttle history.
        Returns None if the throttle is not currently limiting.
        """
        if self.history:
            remaining_duration: float = self.duration - (self.now - self.history[-1])
            if remaining_duration > 0:
                return remaining_duration
        return None

    @staticmethod
    def _log_violation(request: Request, throttle_type: str) -> None:
        """Log throttle violation with request context."""
        logger.warning(
            "throttle_violation",
            extra={
                "throttle_type": throttle_type,
                "user_id": getattr(request.user, "pk", None),
                "path": request.path,
                "method": request.method,
            },
        )


class BurstRateThrottle(SimpleRateThrottle):
    """Burst rate limit for AI assistance: 5 requests per minute per user.

    Provides short-term burst protection alongside the sustained hourly limit.
    Anonymous users are blocked.
    """

    scope: str = "ai_assist_burst"
    rate: str = "5/min"
    cache_format: str = "mltask:throttle:%(scope)s:%(ident)s"

    def get_cache_key(self, request: Request, view: View) -> str | None:
        """Generate per-user cache key. Returns None for anonymous users."""
        if not request.user or not request.user.is_authenticated:
            return None
        ident: str = str(request.user.pk)
        return self.cache_format % {"scope": self.scope, "ident": ident}

    def allow_request(self, request: Request, view: View) -> bool:
        """Check burst rate limit and log violations."""
        allowed: bool = super().allow_request(request, view)
        if not allowed:
            self._log_violation(request, "ai_assist_burst")
        return allowed

    def wait(self) -> float | None:
        """Return seconds until the next request is allowed."""
        if self.history:
            remaining_duration: float = self.duration - (self.now - self.history[-1])
            if remaining_duration > 0:
                return remaining_duration
        return None

    @staticmethod
    def _log_violation(request: Request, throttle_type: str) -> None:
        """Log throttle violation with request context."""
        logger.warning(
            "throttle_violation",
            extra={
                "throttle_type": throttle_type,
                "user_id": getattr(request.user, "pk", None),
                "path": request.path,
                "method": request.method,
            },
        )