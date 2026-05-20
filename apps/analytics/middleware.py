"""Analytics middleware for multilingual-task-api.

Provides zero-overhead request timing and structured logging without
issuing any database queries. Reads all metadata from the request object.
"""

from __future__ import annotations

import logging
import time
from typing import Callable

from django.http import HttpRequest, HttpResponse


logger: logging.Logger = logging.getLogger(__name__)


class RequestTimingMiddleware:
    """Record request duration and emit structured timing logs.

    Uses time.perf_counter() for high-resolution elapsed time measurement.
    Adds an X-Response-Time header to every response. All metadata is
    sourced from the request object — no database queries are issued.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response: Callable[[HttpRequest], HttpResponse] = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        """Time the request and log structured metrics."""
        start_time: float = time.perf_counter()

        response: HttpResponse = self.get_response(request)

        duration_s: float = time.perf_counter() - start_time
        duration_ms: float = duration_s * 1000.0

        # Attach timing header (2 decimal places)
        response["X-Response-Time"] = f"{duration_ms:.2f}"

        # Extract metadata from request only — zero DB queries
        user_id: str | None = self._get_user_id(request)
        correlation_id: str | None = getattr(request, "correlation_id", None)
        language: str | None = getattr(request, "language", None)

        logger.info(
            "request_timing",
            extra={
                "method": request.method,
                "path": request.path,
                "status_code": response.status_code,
                "duration_ms": round(duration_ms, 2),
                "correlation_id": correlation_id,
                "user_id": user_id,
                "language": language,
            },
        )

        return response

    @staticmethod
    def _get_user_id(request: HttpRequest) -> str | None:
        """Safely extract user ID without triggering DB queries.

        Checks for authentication state via the user attribute without
        accessing lazy-loaded profile fields.
        """
        user = getattr(request, "user", None)
        if user is None:
            return None
        if not getattr(user, "is_authenticated", False):
            return None
        # Use pk to avoid __str__ or property access that may query DB
        user_pk = getattr(user, "pk", None)
        return str(user_pk) if user_pk is not None else None