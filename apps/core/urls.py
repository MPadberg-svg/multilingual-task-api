"""URL routing for core platform endpoints.

Exposes:
    - Health check: ``/api/v1/health/``
    - Readiness probe: ``/api/v1/ready/``
    - Prometheus metrics: ``/api/v1/metrics/``
"""

from django.urls import path

from apps.core.views import HealthCheckView, MetricsView, ReadinessView

urlpatterns = [
    path("health/", HealthCheckView.as_view(), name="health-check"),
    path("ready/", ReadinessView.as_view(), name="readiness-check"),
    path("metrics/", MetricsView.as_view(), name="metrics"),
]