"""Tests for core health, readiness, and Prometheus metrics endpoints."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db.utils import OperationalError
from django.test import override_settings

import pytest
from redis.exceptions import RedisError
from rest_framework.test import APIClient

from apps.core.views import (
    CACHE_HIT_KEY,
    CACHE_MISS_KEY,
    REQUEST_COUNT_KEY,
    record_cache_hit,
    record_cache_miss,
)

User = get_user_model()


@pytest.mark.django_db
class TestLiveness:
    """Tests for the /api/v1/live/ liveness probe endpoint."""

    def setup_method(self) -> None:
        self.client = APIClient()
        cache.clear()

    def test_live_returns_200(self) -> None:
        """Liveness endpoint must return HTTP 200 immediately."""
        response = self.client.get("/api/v1/live/")
        assert response.status_code == 200

    def test_live_contains_status_alive(self) -> None:
        """Response must contain {'status': 'alive'}."""
        response = self.client.get("/api/v1/live/")
        data = response.json()
        assert data == {"status": "alive"}

    def test_live_is_public_no_auth_required(self) -> None:
        """Liveness endpoint must be accessible without authentication."""
        client = APIClient()
        response = client.get("/api/v1/live/")
        assert response.status_code == 200

    def test_live_not_blocked_by_100_per_day_anon_throttle(self) -> None:
        """Orchestrator probes (>100 requests) must not trigger 429 from anon 100/day limit."""
        client = APIClient()
        for _ in range(110):
            response = client.get("/api/v1/live/")
            assert response.status_code == 200


@pytest.mark.django_db
class TestHealthCheck:
    """Tests for the /api/v1/health/ endpoint."""

    def setup_method(self) -> None:
        self.client = APIClient()
        cache.clear()

    def test_health_returns_200(self) -> None:
        """Health endpoint must return HTTP 200 when DB and cache are healthy."""
        response = self.client.get("/api/v1/health/")
        assert response.status_code == 200

    def test_health_contains_status_ok(self) -> None:
        """Response must contain 'status': 'ok' when dependencies are healthy."""
        response = self.client.get("/api/v1/health/")
        data = response.json()
        assert data["status"] == "ok"

    def test_health_checks_db_and_redis(self) -> None:
        """Response must contain 'checks' with 'db' and 'redis' sub-keys."""
        response = self.client.get("/api/v1/health/")
        data = response.json()
        assert "checks" in data
        assert "db" in data["checks"]
        assert "redis" in data["checks"]

    def test_health_is_public_no_auth_required(self) -> None:
        """Health endpoint must be accessible without any authentication."""
        client = APIClient()
        response = client.get("/api/v1/health/")
        assert response.status_code == 200

    def test_health_returns_503_and_redacts_internal_db_error(self) -> None:
        """Database failure must return HTTP 503 without leaking internal host details."""
        with patch(
            "apps.core.views.connection.cursor",
            side_effect=OperationalError("FATAL: password auth failed at rds.internal:5432"),
        ):
            response = self.client.get("/api/v1/health/")

        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "degraded"
        assert data["checks"]["db"]["status"] == "down"
        assert "rds.internal" not in str(data)
        assert "password" not in str(data)

    def test_health_returns_503_and_redacts_internal_redis_error(self) -> None:
        """Redis failure must return HTTP 503 without leaking internal host details."""
        failing_redis = MagicMock()
        failing_redis.ping.side_effect = RedisError("Error connecting to redis.internal:6379")
        with patch("apps.core.views.get_redis_connection", return_value=failing_redis):
            response = self.client.get("/api/v1/health/")

        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "degraded"
        assert data["checks"]["redis"]["status"] == "down"
        assert "redis.internal" not in str(data)

    def test_health_locmem_fallback_succeeds(self) -> None:
        """LocMemCache fallback must report status 'ok' when Redis client is unsupported."""
        with patch("apps.core.views.get_redis_connection", side_effect=NotImplementedError):
            response = self.client.get("/api/v1/health/")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["checks"]["redis"]["status"] == "ok"


@pytest.mark.django_db
class TestReadiness:
    """Tests for the /api/v1/ready/ readiness probe endpoint."""

    def setup_method(self) -> None:
        self.client = APIClient()
        cache.clear()

    def test_readiness_returns_200_when_healthy(self) -> None:
        """Readiness must return 200 when DB and cache are healthy."""
        response = self.client.get("/api/v1/ready/")
        assert response.status_code == 200
        assert response.json()["status"] == "ready"

    def test_readiness_is_public_no_auth_required(self) -> None:
        """Readiness endpoint must be accessible without JWT token."""
        client = APIClient()
        response = client.get("/api/v1/ready/")
        assert response.status_code == 200

    def test_readiness_returns_503_when_db_fails_without_leaking_details(self) -> None:
        """Readiness must return 503 and sanitize DB error details."""
        with patch(
            "apps.core.views.connection.ensure_connection",
            side_effect=OperationalError("secret-db-host.internal refused connection"),
        ):
            response = self.client.get("/api/v1/ready/")

        assert response.status_code == 503
        body = response.json()
        assert body["status"] == "not_ready"
        assert "secret-db-host" not in str(body)

    def test_readiness_returns_503_when_cache_fails(self) -> None:
        """Readiness must return 503 if cache roundtrip fails."""
        with patch("apps.core.views.cache.get", return_value="corrupted"):
            response = self.client.get("/api/v1/ready/")

        assert response.status_code == 503
        assert response.json()["status"] == "not_ready"


@pytest.mark.django_db
class TestMetrics:
    """Tests for the /api/v1/metrics/ Prometheus exposition endpoint."""

    def setup_method(self) -> None:
        self.client = APIClient()
        cache.clear()

    def test_metrics_returns_valid_prometheus_plaintext(self) -> None:
        """Metrics endpoint must return unquoted Prometheus exposition text, not JSON."""
        response = self.client.get("/api/v1/metrics/")
        assert response.status_code == 200
        assert response["Content-Type"].startswith("text/plain; version=0.0.4")
        content = response.content.decode()
        assert content.startswith("# HELP mltask_http_requests_total")
        assert not content.startswith('"')
        assert "\\n" not in content

    def test_metrics_contains_redis_and_request_stats(self) -> None:
        """Response must reflect incremented request and cache hit/miss counters."""
        cache.set(REQUEST_COUNT_KEY, 0)
        cache.set(CACHE_HIT_KEY, 0)
        cache.set(CACHE_MISS_KEY, 0)

        # Trigger live HTTP requests + cache hit/miss instrumentation
        self.client.get("/api/v1/live/")
        record_cache_hit()
        record_cache_hit()
        record_cache_hit()
        record_cache_miss()

        response = self.client.get("/api/v1/metrics/")
        content = response.content.decode()
        assert "mltask_http_requests_total 1" in content
        assert "mltask_cache_hits_total 3" in content
        assert "mltask_cache_misses_total 1" in content
        assert "mltask_cache_hit_rate 0.7500" in content

    @override_settings(METRICS_AUTH_TOKEN="super-secret-scrape-token")
    def test_metrics_enforces_scrape_token_when_configured(self) -> None:
        """When METRICS_AUTH_TOKEN is set, unauthorized scrapes must receive 403."""
        assert self.client.get("/api/v1/metrics/").status_code == 403
        assert (
            self.client.get(
                "/api/v1/metrics/",
                HTTP_X_METRICS_TOKEN="wrong-token",
            ).status_code
            == 403
        )
        assert (
            self.client.get(
                "/api/v1/metrics/",
                HTTP_X_METRICS_TOKEN="super-secret-scrape-token",
            ).status_code
            == 200
        )
        assert (
            self.client.get(
                "/api/v1/metrics/",
                HTTP_AUTHORIZATION="Bearer super-secret-scrape-token",
            ).status_code
            == 200
        )

    @override_settings(METRICS_AUTH_TOKEN="super-secret-scrape-token")
    def test_metrics_allows_authenticated_staff_user(self) -> None:
        """Staff users can inspect metrics even when METRICS_AUTH_TOKEN is enabled."""
        staff = User.objects.create_user(
            email="ops@example.com",
            password="testpass123",
            is_staff=True,
        )
        self.client.force_authenticate(user=staff)
        assert self.client.get("/api/v1/metrics/").status_code == 200
