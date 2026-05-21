"""Root URL configuration for the multilingual task API.

Exposes:
    - Django Admin
    - Authentication (JWT): ``/api/v1/auth/token/``, ``/api/v1/auth/token/refresh/``, ``/api/v1/auth/token/verify/``
    - Task API: ``/api/v1/tasks/``
    - AI Assist API: ``/api/v1/ai/``
    - Core API: ``/api/v1/`` (health, metrics)
    - GraphQL: ``/graphql/``
    - OpenAPI Schema: ``/api/schema/``
    - Swagger UI: ``/api/docs/``
    - ReDoc: ``/api/redoc/``
"""

from django.contrib import admin
from django.urls import include, path
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)
from strawberry.django.views import AsyncGraphQLView

from apps.core.graphql.schema import schema as graphql_schema

urlpatterns = [
    # Django Admin
    path("admin/", admin.site.urls),
    
    # JWT Authentication Endpoints
    path("api/v1/auth/token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("api/v1/auth/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("api/v1/auth/token/verify/", TokenVerifyView.as_view(), name="token_verify"),
    
    # Application APIs
    path("api/v1/tasks/", include("apps.tasks.urls")),
    path("api/v1/ai/", include("apps.ai_assist.urls")),
    path("api/v1/", include("apps.core.urls")),
    
    # GraphQL Engine
    path("graphql/", AsyncGraphQLView.as_view(schema=graphql_schema)),
    
    # OpenAPI 3.0 Documentation & Schemas (Explicitly exempted from global auth)
    path(
        "api/schema/", 
        SpectacularAPIView.as_view(permission_classes=[AllowAny], authentication_classes=[]), 
        name="schema"
    ),
    path(
        "api/docs/",
        SpectacularSwaggerView.as_view(url_name="schema", permission_classes=[AllowAny], authentication_classes=[]),
        name="swagger-ui",
    ),
    path(
        "api/redoc/",
        SpectacularRedocView.as_view(url_name="schema", permission_classes=[AllowAny], authentication_classes=[]),
        name="redoc",
    ),
]