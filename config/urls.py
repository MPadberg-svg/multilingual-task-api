"""Root URL configuration for the multilingual task API.

Exposes:
    - Django Admin
    - Task API: ``/api/v1/tasks/``
    - AI Assist API: ``/api/v1/ai/``
    - Core API: ``/api/v1/`` (health, metrics)
    - GraphQL: ``/graphql/``
    - OpenAPI Schema: ``/api/schema/``
    - Swagger UI: ``/api/docs/``
"""

from django.contrib import admin
from django.urls import include, path
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)
from strawberry.django.views import AsyncGraphQLView

from apps.core.graphql.schema import schema as graphql_schema

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/v1/tasks/", include("apps.tasks.urls")),
    path("api/v1/ai/", include("apps.ai_assist.urls")),
    path("api/v1/", include("apps.core.urls")),
    path("graphql/", AsyncGraphQLView.as_view(schema=graphql_schema)),
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path(
        "api/docs/",
        SpectacularSwaggerView.as_view(url_name="schema"),
        name="swagger-ui",
    ),
    path(
        "api/redoc/",
        SpectacularRedocView.as_view(url_name="schema"),
        name="redoc",
    ),
]