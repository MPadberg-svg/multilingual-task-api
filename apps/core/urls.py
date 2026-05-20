"""URL routing for core platform endpoints."""

from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from apps.core.views import HealthCheckView, MetricsView

urlpatterns = [
    path("health/", HealthCheckView.as_view(), name="health-check"),
    path("metrics/", MetricsView.as_view(), name="metrics"),
    path("auth/token/", TokenObtainPairView.as_view(), name="token-obtain-pair"),
    path("auth/token/refresh/", TokenRefreshView.as_view(), name="token-refresh"),
]
