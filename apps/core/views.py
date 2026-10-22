"""Core API views for health checks, readiness, and Prometheus metrics."""

from __future__ import annotations

import hmac
import logging
import time
from typing import Any

from django.conf import settings
from django.core.cache import cache
from django.db import connection
from django.db.utils import DatabaseError, OperationalError
from django.http import HttpResponse
from django.utils import timezone

from django_redis import get_redis_connection
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiResponse, extend_schema, inline_serializer
from redis.exceptions import RedisError
from rest_framework import serializers, status
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.core.throttling import HealthCheckAnonRateThrottle

logger = logging.getLogger(__name__)

REQUEST_COUNT_KEY = "mltask:metrics:requests_total"
CACHE_HIT_KEY = "mltask:metrics:cache_hits"
CACHE_MISS_KEY = "mltask:metrics:cache_misses"


def _coerce_int(value: Any) -> int:
    """Coerce cached counter values to integers."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return 0


def increment_metric(key: str, delta: int = 1) -> None:
    """Atomically increment a cache-backed observability counter.

    Never raises: metrics collection must not degrade request serving if
    the cache backend is transiently unavailable.
    """
    try:
        cache.incr(key, delta)
    except ValueError:
        try:
            if not cache.add(key, delta, timeout=None):
                cache.incr(key, delta)
        except Exception:
            logger.debug("Unable to initialize metric counter %s", key, exc_info=True)
    except Exception:
        logger.debug("Unable to increment metric counter %s", key, exc_info=True)


def record_cache_hit() -> None:
    """Increment the global Redis/cache hit counter."""
    increment_metric(CACHE_HIT_KEY)


def record_cache_miss() -> None:
    """Increment the global Redis/cache miss counter."""
    increment_metric(CACHE_MISS_KEY)


class LivenessView(APIView):
    """Lightweight liveness probe — returns 200 if the app process is running.

    Docker/Kubernetes uses this to know if the container should be restarted.
    No external dependency checks — just confirms Django is alive.
    """

    authentication_classes: list[Any] = []
    permission_classes = [AllowAny]
    throttle_classes = [HealthCheckAnonRateThrottle]

    @extend_schema(
        summary="Container liveness probe",
        responses={
            200: inline_serializer(
                name="LivenessResponse",
                fields={"status": serializers.CharField()},
            )
        },
    )
    def get(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        return Response({"status": "alive"})


class HealthCheckView(APIView):
    """Health check endpoint for core dependencies.

    Checks DB and cache connectivity only. OpenAI is excluded to avoid slow
    or billable upstream calls on frequent orchestrator probes. Returns HTTP
    200 when healthy and HTTP 503 when any dependency is down.
    """

    authentication_classes: list[Any] = []
    permission_classes = [AllowAny]
    throttle_classes = [HealthCheckAnonRateThrottle]

    @extend_schema(
        summary="Dependency health check",
        responses={
            200: inline_serializer(
                name="HealthCheckResponse",
                fields={
                    "status": serializers.CharField(),
                    "timestamp": serializers.DateTimeField(),
                    "checks": serializers.DictField(),
                },
            ),
            503: OpenApiResponse(description="One or more dependencies are degraded/down."),
        },
    )
    def get(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """Return connectivity status for DB and cache."""
        checks = {
            "db": self._check_db(),
            "redis": self._check_redis(),
        }
        is_healthy = all(result["status"] == "ok" for result in checks.values())
        overall_status = "ok" if is_healthy else "degraded"
        http_status = status.HTTP_200_OK if is_healthy else status.HTTP_503_SERVICE_UNAVAILABLE
        return Response(
            {
                "status": overall_status,
                "timestamp": timezone.now().isoformat(),
                "checks": checks,
            },
            status=http_status,
        )

    @staticmethod
    def _check_db() -> dict[str, Any]:
        """Check database connectivity with a lightweight query."""
        start = time.perf_counter()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                cursor.fetchone()
            return {
                "status": "ok",
                "latency_ms": round((time.perf_counter() - start) * 1000.0, 2),
            }
        except (OperationalError, DatabaseError):
            logger.error("Health check database probe failed", exc_info=True)
            return {"status": "down", "error": "Database unavailable"}

    @staticmethod
    def _check_redis() -> dict[str, Any]:
        """Check Redis connectivity using PING, with cache roundtrip fallback."""
        start = time.perf_counter()
        try:
            redis_conn = get_redis_connection("default")
            redis_conn.ping()
            return {
                "status": "ok",
                "latency_ms": round((time.perf_counter() - start) * 1000.0, 2),
            }
        except NotImplementedError:
            # Non-Redis cache backend (e.g. LocMemCache in testing): verify roundtrip.
            try:
                probe_key = "mltask:health:ping"
                cache.set(probe_key, "pong", timeout=5)
                if cache.get(probe_key) != "pong":
                    raise RuntimeError("Cache probe read/write mismatch")
                return {
                    "status": "ok",
                    "backend": "locmem",
                    "latency_ms": round((time.perf_counter() - start) * 1000.0, 2),
                }
            except Exception:
                logger.error("Health check fallback cache probe failed", exc_info=True)
                return {"status": "down", "error": "Cache unavailable"}
        except RedisError:
            logger.error("Health check Redis probe failed", exc_info=True)
            return {"status": "down", "error": "Cache unavailable"}


class ReadinessView(APIView):
    """Kubernetes/ECS readiness probe.

    Returns 200 only when database AND cache are reachable.
    ALB/ECS stops routing traffic if this returns 503.
    """

    authentication_classes: list[Any] = []
    permission_classes = [AllowAny]
    throttle_classes = [HealthCheckAnonRateThrottle]

    @extend_schema(
        summary="Service readiness probe",
        responses={
            200: inline_serializer(
                name="ReadinessResponse",
                fields={
                    "status": serializers.CharField(),
                    "checks": serializers.DictField(),
                },
            ),
            503: OpenApiResponse(description="Service is not ready to receive traffic."),
        },
    )
    def get(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        checks: dict[str, dict[str, Any]] = {}
        is_ready = True

        # Database check
        start = time.monotonic()
        try:
            connection.ensure_connection()
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
            checks["database"] = {
                "status": "ok",
                "latency_ms": round((time.monotonic() - start) * 1000, 2),
            }
        except (OperationalError, DatabaseError):
            logger.error("Readiness database probe failed", exc_info=True)
            checks["database"] = {"status": "error", "detail": "Database unavailable"}
            is_ready = False

        # Cache check
        start = time.monotonic()
        try:
            cache.set("readiness_ping", "pong", timeout=5)
            val = cache.get("readiness_ping")
            if val != "pong":
                raise ValueError("Cache read/write mismatch")
            checks["cache"] = {
                "status": "ok",
                "latency_ms": round((time.monotonic() - start) * 1000, 2),
            }
        except Exception:
            logger.error("Readiness cache probe failed", exc_info=True)
            checks["cache"] = {"status": "error", "detail": "Cache unavailable"}
            is_ready = False

        http_status = status.HTTP_200_OK if is_ready else status.HTTP_503_SERVICE_UNAVAILABLE
        return Response(
            {"status": "ready" if is_ready else "not_ready", "checks": checks},
            status=http_status,
        )


class MetricsView(APIView):
    """Prometheus text-format metrics endpoint.

    When ``settings.METRICS_AUTH_TOKEN`` is configured, callers must supply
    a matching ``Authorization: Bearer <token>`` or ``X-Metrics-Token``
    header, or authenticate as a staff user.
    """

    authentication_classes: list[Any] = []
    permission_classes = [AllowAny]
    throttle_classes = [HealthCheckAnonRateThrottle]

    @staticmethod
    def _is_authorized(request: Request) -> bool:
        expected_token: str = getattr(settings, "METRICS_AUTH_TOKEN", "") or ""
        if not expected_token:
            return True

        # 1. Check dedicated scrape token first (supports Prometheus bearer_token & X-Metrics-Token)
        provided = request.headers.get("X-Metrics-Token", "").strip()
        auth_header = request.headers.get("Authorization", "")
        if not provided and auth_header.startswith("Bearer "):
            provided = auth_header[7:].strip()
        if provided and hmac.compare_digest(provided, expected_token):
            return True

        # 2. Allow authenticated staff users (session, force_authenticate, or valid staff JWT)
        user = getattr(request, "user", None)
        if user is not None and getattr(user, "is_authenticated", False) and user.is_staff:
            return True

        if auth_header.startswith("Bearer "):
            from rest_framework_simplejwt.authentication import JWTAuthentication
            from rest_framework_simplejwt.exceptions import InvalidToken, TokenError

            try:
                auth_result = JWTAuthentication().authenticate(request)
                if auth_result is not None:
                    jwt_user, _ = auth_result
                    if getattr(jwt_user, "is_authenticated", False) and getattr(
                        jwt_user, "is_staff", False
                    ):
                        return True
            except (InvalidToken, TokenError, Exception):
                return False

        return False

    @extend_schema(
        summary="Prometheus metrics scrape endpoint",
        responses={
            (200, "text/plain"): OpenApiTypes.STR,
            403: OpenApiResponse(description="Invalid or missing metrics scrape token."),
        },
    )
    def get(self, request: Request, *args: Any, **kwargs: Any) -> HttpResponse | Response:
        """Return Prometheus exposition format metrics."""
        if not self._is_authorized(request):
            return Response(
                {"error": "Forbidden"},
                status=status.HTTP_403_FORBIDDEN,
            )

        request_count = _coerce_int(cache.get(REQUEST_COUNT_KEY, 0))
        cache_hits = _coerce_int(cache.get(CACHE_HIT_KEY, 0))
        cache_misses = _coerce_int(cache.get(CACHE_MISS_KEY, 0))
        total_cache = cache_hits + cache_misses
        cache_hit_rate = (cache_hits / total_cache) if total_cache else 0.0

        metrics = [
            "# HELP mltask_http_requests_total Total HTTP requests handled.",
            "# TYPE mltask_http_requests_total counter",
            f"mltask_http_requests_total {request_count}",
            "# HELP mltask_cache_hits_total Total application cache hits.",
            "# TYPE mltask_cache_hits_total counter",
            f"mltask_cache_hits_total {cache_hits}",
            "# HELP mltask_cache_misses_total Total application cache misses.",
            "# TYPE mltask_cache_misses_total counter",
            f"mltask_cache_misses_total {cache_misses}",
            "# HELP mltask_cache_hit_rate Cache hit rate across Redis-backed endpoints.",
            "# TYPE mltask_cache_hit_rate gauge",
            f"mltask_cache_hit_rate {cache_hit_rate:.4f}",
        ]
        return HttpResponse(
            "\n".join(metrics) + "\n",
            content_type="text/plain; version=0.0.4; charset=utf-8",
        )
