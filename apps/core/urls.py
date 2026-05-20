"""URL routing for core platform endpoints.

Exposes:
    - Health check: ``/api/v1/health/``
    - Prometheus metrics: ``/api/v1/metrics/``
"""

from django.urls import path

from apps.core.views import HealthCheckView, MetricsView

urlpatterns = [
    path("health/", HealthCheckView.as_view(), name="health-check"),
    path("metrics/", MetricsView.as_view(), name="metrics"),
]