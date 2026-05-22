"""URL routing for core platform endpoints.

Exposes:
    - Liveness probe: ``/api/v1/live/`` (lightweight, for Docker healthcheck)
    - Health check: ``/api/v1/health/`` (DB + Redis only)
    - Readiness probe: ``/api/v1/ready/`` (DB + Redis, returns 503 if down)
    - Prometheus metrics: ``/api/v1/metrics/``
"""

from django.urls import path

from apps.core.views import HealthCheckView, LivenessView, MetricsView, ReadinessView

urlpatterns = [
    path("live/", LivenessView.as_view(), name="live"),
    path("health/", HealthCheckView.as_view(), name="health-check"),
    path("ready/", ReadinessView.as_view(), name="readiness-check"),
    path("metrics/", MetricsView.as_view(), name="metrics"),
]