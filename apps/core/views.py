"""Core API views for health checks and metrics."""

from __future__ import annotations

import time
from typing import Any

from django.conf import settings
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


class HealthCheckView(APIView):
    """Health check endpoint for dependencies."""

    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs) -> Response:
        """Return connectivity status for core dependencies."""
        checks = {
            "db": self._check_db(),
            "redis": self._check_redis(),
            "openai": self._check_openai(),
        }
        overall_status = "ok" if all(
            result["status"] == "ok" for result in checks.values()
        ) else "degraded"
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
        except (OperationalError, DatabaseError) as exc:
            return {"status": "down", "error": str(exc)}

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
        except RedisError as exc:
            return {"status": "down", "error": str(exc)}

    @staticmethod
    def _check_openai() -> dict[str, Any]:
        """Check OpenAI API connectivity when configured."""
        if not settings.OPENAI_API_KEY:
            return {"status": "not_configured"}
        try:
            import openai
            from openai import OpenAIError
        except ImportError as exc:
            return {"status": "not_installed", "error": str(exc)}

        start = time.perf_counter()
        try:
            client = openai.OpenAI(
                api_key=settings.OPENAI_API_KEY,
                timeout=5.0,
                max_retries=0,
            )
            client.models.list()
            return {
                "status": "ok",
                "latency_ms": round((time.perf_counter() - start) * 1000.0, 2),
            }
        except OpenAIError as exc:
            return {"status": "down", "error": str(exc)}


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
