"""Root URL configuration for multilingual-task-api.

Wires the admin interface, health check, authentication, task management,
AI assistance endpoints, and OpenAPI schema documentation.
"""

from __future__ import annotations

from django.contrib import admin
from django.urls import path, include

from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView


urlpatterns: list = [
    path("admin/", admin.site.urls),
    # Health check endpoint
    path("api/v1/health/", include("apps.core.urls")),
    # Authentication endpoints (JWT login/refresh/verify)
    path("api/v1/auth/", include("apps.core.urls")),
    # Task management endpoints
    path("api/v1/tasks/", include("apps.tasks.urls")),
    # AI assistance endpoints
    path("api/v1/ai/", include("apps.ai_assist.urls")),
    # OpenAPI schema and documentation
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path(
        "api/docs/",
        SpectacularSwaggerView.as_view(url_name="schema"),
        name="swagger-ui",
    ),
]