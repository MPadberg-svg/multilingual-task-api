"""Core API views for health checks, readiness, and metrics."""

from __future__ import annotations

import time
from typing import Any

from django.core.cache import cache
from django.db import connection
from django.db.utils import DatabaseError, OperationalError
from django.utils import timezone

from django_redis import get_redis_connection
from redis.exceptions import RedisError
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

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


class LivenessView(APIView):
    """Lightweight liveness probe — returns 200 if the app process is running.

    Docker/Kubernetes uses this to know if the container should be restarted.
    No external dependency checks — just confirms Django is alive.
    """

    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs) -> Response:
        return Response({"status": "alive"})


class HealthCheckView(APIView):
    """Health check endpoint for core dependencies.

    Checks DB and Redis only. OpenAI is excluded to avoid slow/heavy
    calls on frequent health probes.
    """

    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs) -> Response:
        """Return connectivity status for DB and Redis."""
        checks = {
            "db": self._check_db(),
            "redis": self._check_redis(),
        }
        overall_status = (
            "ok" if all(result["status"] == "ok" for result in checks.values()) else "degraded"
        )
        return Response(
            {
                "status": overall_status,
                "timestamp": timezone.now().isoformat(),
                "checks": checks,
            },
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
            return {"status": "down", "error": "database_unavailable"}

    @staticmethod
    def _check_redis() -> dict[str, Any]:
        """Check Redis connectivity using a ping."""
        start = time.perf_counter()
        try:
            redis_conn = get_redis_connection("default")
            redis_conn.ping()
            return {
                "status": "ok",
                "latency_ms": round((time.perf_counter() - start) * 1000.0, 2),
            }
        except (RedisError, Exception):
            return {"status": "down", "error": "redis_unavailable"}


class ReadinessView(APIView):
    """
    Kubernetes/ECS readiness probe.
    Returns 200 only when database AND Redis are reachable.
    ALB/ECS will stop routing traffic if this returns 503.
    """

    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs) -> Response:
        checks = {}
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
            checks["database"] = {"status": "error", "detail": "database_unavailable"}
            is_ready = False

        # Redis check
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
            checks["cache"] = {"status": "error", "detail": "cache_unavailable"}
            is_ready = False

        http_status = 200 if is_ready else 503
        return Response(
            {"status": "ready" if is_ready else "not_ready", "checks": checks},
            status=http_status,
        )


class MetricsView(APIView):
    """Prometheus-style metrics endpoint."""

    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs) -> Response:
        """Return basic metrics for scraping."""
        request_count = _coerce_int(cache.get(REQUEST_COUNT_KEY, 0))
        cache_hits = _coerce_int(cache.get(CACHE_HIT_KEY, 0))
        cache_misses = _coerce_int(cache.get(CACHE_MISS_KEY, 0))
        total_cache = cache_hits + cache_misses
        cache_hit_rate = (cache_hits / total_cache) if total_cache else 0.0

        metrics = [
            "# HELP mltask_http_requests_total Total HTTP requests handled.",
            "# TYPE mltask_http_requests_total counter",
            f"mltask_http_requests_total {request_count}",
            "# HELP mltask_cache_hit_rate Cache hit rate across Redis-backed endpoints.",
            "# TYPE mltask_cache_hit_rate gauge",
            f"mltask_cache_hit_rate {cache_hit_rate:.4f}",
        ]
        return Response(
            "\n".join(metrics) + "\n",
            content_type="text/plain; version=0.0.4",
        )
