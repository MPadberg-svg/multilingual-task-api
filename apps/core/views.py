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

from apps.core.finops import record_org_ai_spend_and_alerts
from apps.core.models import OutboxEvent
from apps.core.rls import rls_bypass
from apps.core.throttling import HealthCheckAnonRateThrottle

logger = logging.getLogger(__name__)

REQUEST_COUNT_KEY = "mltask:metrics:requests_total"
CACHE_HIT_KEY = "mltask:metrics:cache_hits"
CACHE_MISS_KEY = "mltask:metrics:cache_misses"
AI_REQUESTS_KEY = "mltask:metrics:ai_requests_total"
AI_PROMPT_TOKENS_KEY = "mltask:metrics:ai_prompt_tokens_total"
AI_COMPLETION_TOKENS_KEY = "mltask:metrics:ai_completion_tokens_total"
AI_COST_NANOUSD_KEY = "mltask:metrics:ai_cost_nanousd_total"

# Published GPT-4o-mini rates: $0.15 / 1M input tokens (150 nano-USD/token),
# $0.60 / 1M output tokens (600 nano-USD/token)
_INPUT_TOKEN_NANOUSD = 150
_OUTPUT_TOKEN_NANOUSD = 600


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


def record_ai_token_usage(
    prompt_tokens: int,
    completion_tokens: int,
    organization_id: str | None = None,
    *,
    user_id: str | None = None,
    operation: str = "chat.completions",
    model_name: str | None = None,
) -> None:
    """Record global and per-organization OpenAI token and estimated USD cost telemetry."""
    p_tok = max(0, int(prompt_tokens))
    c_tok = max(0, int(completion_tokens))
    cost_nanousd = (p_tok * _INPUT_TOKEN_NANOUSD) + (c_tok * _OUTPUT_TOKEN_NANOUSD)

    increment_metric(AI_REQUESTS_KEY, 1)
    if p_tok:
        increment_metric(AI_PROMPT_TOKENS_KEY, p_tok)
    if c_tok:
        increment_metric(AI_COMPLETION_TOKENS_KEY, c_tok)
    if cost_nanousd:
        increment_metric(AI_COST_NANOUSD_KEY, cost_nanousd)

    if organization_id:
        prefix = f"mltask:usage:ai:{organization_id}"
        increment_metric(f"{prefix}:requests", 1)
        if p_tok:
            increment_metric(f"{prefix}:prompt_tokens", p_tok)
        if c_tok:
            increment_metric(f"{prefix}:completion_tokens", c_tok)
        if cost_nanousd:
            increment_metric(f"{prefix}:cost_nanousd", cost_nanousd)
        record_org_ai_spend_and_alerts(
            organization_id=organization_id,
            prompt_tokens=p_tok,
            completion_tokens=c_tok,
            cost_nanousd=cost_nanousd,
            user_id=user_id,
            operation=operation,
            model_name=model_name,
        )


def get_org_ai_usage(organization_id: str) -> dict[str, int | float]:
    """Read cumulative and rolling-daily AI usage telemetry for an organization."""
    prefix = f"mltask:usage:ai:{organization_id}"
    daily_used = _coerce_int(cache.get(f"mltask:quota:ai:{organization_id}", 0))
    req_total = _coerce_int(cache.get(f"{prefix}:requests", 0))
    prompt_tok = _coerce_int(cache.get(f"{prefix}:prompt_tokens", 0))
    comp_tok = _coerce_int(cache.get(f"{prefix}:completion_tokens", 0))
    cost_nanousd = _coerce_int(cache.get(f"{prefix}:cost_nanousd", 0))
    return {
        "requests_daily": daily_used,
        "requests_total": req_total,
        "prompt_tokens": prompt_tok,
        "completion_tokens": comp_tok,
        "estimated_cost_usd": round(cost_nanousd / 1_000_000_000, 6),
    }


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

        ai_requests = _coerce_int(cache.get(AI_REQUESTS_KEY, 0))
        ai_prompt_tokens = _coerce_int(cache.get(AI_PROMPT_TOKENS_KEY, 0))
        ai_completion_tokens = _coerce_int(cache.get(AI_COMPLETION_TOKENS_KEY, 0))
        ai_cost_usd = _coerce_int(cache.get(AI_COST_NANOUSD_KEY, 0)) / 1_000_000_000

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
            "# HELP mltask_ai_requests_total Total upstream OpenAI requests completed.",
            "# TYPE mltask_ai_requests_total counter",
            f"mltask_ai_requests_total {ai_requests}",
            "# HELP mltask_ai_prompt_tokens_total Total OpenAI prompt tokens consumed.",
            "# TYPE mltask_ai_prompt_tokens_total counter",
            f"mltask_ai_prompt_tokens_total {ai_prompt_tokens}",
            "# HELP mltask_ai_completion_tokens_total Total OpenAI completion tokens consumed.",
            "# TYPE mltask_ai_completion_tokens_total counter",
            f"mltask_ai_completion_tokens_total {ai_completion_tokens}",
            "# HELP mltask_ai_estimated_cost_usd_total Estimated cumulative OpenAI spend in USD.",
            "# TYPE mltask_ai_estimated_cost_usd_total counter",
            f"mltask_ai_estimated_cost_usd_total {ai_cost_usd:.6f}",
        ]

        outbox_pending = 0
        outbox_dead_letter = 0
        try:
            with rls_bypass():
                outbox_pending = OutboxEvent.objects.filter(status="pending").count()
                outbox_dead_letter = OutboxEvent.objects.filter(status="failed").count()
        except (DatabaseError, OperationalError):
            logger.debug("Skipping Outbox Prometheus gauges due to transient DB unavailability.")

        metrics.extend(
            [
                "# HELP mltask_outbox_pending_events Current pending Transactional Outbox events.",
                "# TYPE mltask_outbox_pending_events gauge",
                f"mltask_outbox_pending_events {outbox_pending}",
                "# HELP mltask_outbox_dead_letter_events Current dead-letter Outbox events.",
                "# TYPE mltask_outbox_dead_letter_events gauge",
                f"mltask_outbox_dead_letter_events {outbox_dead_letter}",
            ]
        )
        return HttpResponse(
            "\n".join(metrics) + "\n",
            content_type="text/plain; version=0.0.4; charset=utf-8",
        )
