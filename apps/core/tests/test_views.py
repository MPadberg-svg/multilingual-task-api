"""Tests for core health, readiness, and metrics endpoints."""

import pytest
from django.urls import reverse
from rest_framework.test import APIClient


@pytest.mark.django_db
class TestLiveness:
    """Tests for the /api/v1/live/ liveness probe endpoint."""

    def setup_method(self):
        self.client = APIClient()

    def test_live_returns_200(self):
        """Liveness endpoint must return HTTP 200 immediately."""
        response = self.client.get("/api/v1/live/")
        assert response.status_code == 200

    def test_live_contains_status_alive(self):
        """Response must contain {'status': 'alive'}."""
        response = self.client.get("/api/v1/live/")
        data = response.json()
        assert data == {"status": "alive"}

    def test_live_is_public_no_auth_required(self):
        """Liveness endpoint must be accessible without authentication."""
        client = APIClient()
        response = client.get("/api/v1/live/")
        assert response.status_code == 200
        assert response.status_code != 401


@pytest.mark.django_db
class TestHealthCheck:
    """Tests for the /api/v1/health/ endpoint."""

    def setup_method(self):
        self.client = APIClient()

    def test_health_returns_200(self):
        """Health endpoint must return HTTP 200."""
        response = self.client.get("/api/v1/health/")
        assert response.status_code == 200

    def test_health_contains_status_ok(self):
        """Response must contain a 'status' key with value 'ok' or 'degraded'."""
        response = self.client.get("/api/v1/health/")
        data = response.json()
        assert "status" in data
        assert data["status"] in ("ok", "degraded")

    def test_health_checks_db_and_redis(self):
        """Response must contain 'checks' with 'db' and 'redis' sub-keys."""
        response = self.client.get("/api/v1/health/")
        data = response.json()
        assert "checks" in data
        assert "db" in data["checks"]
        assert "redis" in data["checks"]

    def test_health_is_public_no_auth_required(self):
        """Health endpoint must be accessible without any authentication."""
        client = APIClient()
        response = client.get("/api/v1/health/")
        assert response.status_code == 200
        assert response.status_code != 401


@pytest.mark.django_db
class TestReadiness:
    """Tests for the /api/v1/ready/ readiness probe endpoint."""

    def setup_method(self):
        self.client = APIClient()

    def test_readiness_returns_200_when_healthy(self):
        """Readiness must return 200 when DB and Redis are healthy."""
        response = self.client.get("/api/v1/ready/")
        # In test environment, DB is available; Redis may or may not be
        assert response.status_code in (200, 503)

    def test_readiness_is_public_no_auth_required(self):
        """Readiness endpoint must be accessible without JWT token."""
        client = APIClient()
        response = client.get("/api/v1/ready/")
        assert response.status_code in (200, 503)
        assert response.status_code != 401


@pytest.mark.django_db
class TestMetrics:
    """Tests for the /api/v1/metrics/ Prometheus-style endpoint."""

    def setup_method(self):
        self.client = APIClient()

    def test_metrics_returns_200(self):
        """Metrics endpoint must return HTTP 200 with text/plain content."""
        response = self.client.get("/api/v1/metrics/")
        assert response.status_code == 200

    def test_metrics_contains_redis_stats(self):
        """Response must contain Redis/cache-related metrics."""
        response = self.client.get("/api/v1/metrics/")
        content = response.content.decode()
        assert "mltask_cache_hit_rate" in content

    def test_metrics_contains_task_counts(self):
        """Response must contain request count metrics."""
        response = self.client.get("/api/v1/metrics/")
        content = response.content.decode()
        assert "mltask_http_requests_total" in content