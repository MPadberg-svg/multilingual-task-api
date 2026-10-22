"""Root URL configuration for the multilingual task API.

Exposes:
    - Django Admin
    - Authentication (JWT): ``/api/v1/auth/token/``, ``/api/v1/auth/token/refresh/``, ``/api/v1/auth/token/verify/``
    - Task API: ``/api/v1/tasks/``
    - AI Assist API: ``/api/v1/ai/``
    - Core API: ``/api/v1/`` (live, health, ready, metrics)
    - GraphQL: ``/graphql/``
    - OpenAPI Schema: ``/api/schema/``
    - Swagger UI: ``/api/docs/``
    - ReDoc: ``/api/redoc/``
"""

from __future__ import annotations

from django.conf import settings
from django.contrib import admin
from django.urls import include, path
from django.views.decorators.csrf import csrf_exempt

from drf_spectacular.views import SpectacularAPIView, SpectacularRedocView, SpectacularSwaggerView
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenVerifyView
from strawberry.django.views import AsyncGraphQLView

from apps.core.graphql.schema import schema as graphql_schema
from apps.core.tenant_views import (
    CurrentUserView,
    ExplorerConsoleView,
    LogoutView,
    OrganizationAPIKeyDetailView,
    OrganizationAPIKeyListCreateView,
    OrganizationAuditLogListView,
    OrganizationDetailView,
    OrganizationListCreateView,
    OrganizationMemberDetailView,
    OrganizationMemberListCreateView,
    OrganizationOutboxListView,
    OrganizationOutboxReplayView,
    OrganizationUsageView,
    OrganizationWebhookDeliveryListView,
    OrganizationWebhookDeliveryReplayView,
    OrganizationWebhookDetailView,
    OrganizationWebhookListCreateView,
    OrganizationWebhookRecoverView,
    OrganizationWebhookTestView,
)

urlpatterns = [
    # Django Admin
    path("admin/", admin.site.urls),
    # JWT Authentication Endpoints
    path(
        "api/v1/auth/token/",
        TokenObtainPairView.as_view(),
        name="token_obtain_pair",
    ),
    path(
        "api/v1/auth/token/refresh/",
        TokenRefreshView.as_view(),
        name="token_refresh",
    ),
    path(
        "api/v1/auth/token/verify/",
        TokenVerifyView.as_view(),
        name="token_verify",
    ),
    path("api/v1/auth/me/", CurrentUserView.as_view(), name="auth-me"),
    path("api/v1/auth/logout/", LogoutView.as_view(), name="auth-logout"),
    # Multi-tenant Organizations, RBAC, Audit Logs, FinOps Usage, API Keys & Webhooks
    path(
        "api/v1/organizations/",
        OrganizationListCreateView.as_view(),
        name="organization-list",
    ),
    path(
        "api/v1/organizations/<uuid:org_id>/",
        OrganizationDetailView.as_view(),
        name="organization-detail",
    ),
    path(
        "api/v1/organizations/<uuid:org_id>/members/",
        OrganizationMemberListCreateView.as_view(),
        name="organization-members",
    ),
    path(
        "api/v1/organizations/<uuid:org_id>/members/<uuid:member_id>/",
        OrganizationMemberDetailView.as_view(),
        name="organization-member-detail",
    ),
    path(
        "api/v1/organizations/<uuid:org_id>/audit-logs/",
        OrganizationAuditLogListView.as_view(),
        name="organization-audit-logs",
    ),
    path(
        "api/v1/organizations/<uuid:org_id>/usage/",
        OrganizationUsageView.as_view(),
        name="organization-usage",
    ),
    path(
        "api/v1/organizations/<uuid:org_id>/api-keys/",
        OrganizationAPIKeyListCreateView.as_view(),
        name="organization-api-keys",
    ),
    path(
        "api/v1/organizations/<uuid:org_id>/api-keys/<uuid:key_id>/",
        OrganizationAPIKeyDetailView.as_view(),
        name="organization-api-key-detail",
    ),
    path(
        "api/v1/organizations/<uuid:org_id>/webhooks/",
        OrganizationWebhookListCreateView.as_view(),
        name="organization-webhooks",
    ),
    path(
        "api/v1/organizations/<uuid:org_id>/webhooks/<uuid:webhook_id>/",
        OrganizationWebhookDetailView.as_view(),
        name="organization-webhook-detail",
    ),
    path(
        "api/v1/organizations/<uuid:org_id>/webhooks/<uuid:webhook_id>/test/",
        OrganizationWebhookTestView.as_view(),
        name="organization-webhook-test",
    ),
    path(
        "api/v1/organizations/<uuid:org_id>/webhooks/<uuid:webhook_id>/recover/",
        OrganizationWebhookRecoverView.as_view(),
        name="organization-webhook-recover",
    ),
    path(
        "api/v1/organizations/<uuid:org_id>/webhooks/<uuid:webhook_id>/deliveries/",
        OrganizationWebhookDeliveryListView.as_view(),
        name="organization-webhook-deliveries",
    ),
    path(
        "api/v1/organizations/<uuid:org_id>/webhooks/<uuid:webhook_id>/deliveries/<uuid:delivery_id>/replay/",
        OrganizationWebhookDeliveryReplayView.as_view(),
        name="organization-webhook-delivery-replay",
    ),
    path(
        "api/v1/organizations/<uuid:org_id>/outbox/",
        OrganizationOutboxListView.as_view(),
        name="organization-outbox-list",
    ),
    path(
        "api/v1/organizations/<uuid:org_id>/outbox/<uuid:event_id>/replay/",
        OrganizationOutboxReplayView.as_view(),
        name="organization-outbox-replay",
    ),
    # Interactive CSP-nonce-hardened API & WebSocket Operations Console
    path("explorer/", ExplorerConsoleView.as_view(), name="api-explorer"),
    # Application APIs
    path("api/v1/tasks/", include("apps.tasks.urls")),
    path("api/v1/ai/", include("apps.ai_assist.urls")),
    path("api/v1/", include("apps.core.urls")),
    # GraphQL Engine (JWT-aware; interactive GraphiQL enabled only in DEBUG)
    path(
        "graphql/",
        csrf_exempt(
            AsyncGraphQLView.as_view(
                schema=graphql_schema,
                graphql_ide="graphiql" if settings.DEBUG else None,
            )
        ),
        name="graphql",
    ),
    # OpenAPI 3.0 Documentation & Schemas (Explicitly exempted from global auth)
    path(
        "api/schema/",
        SpectacularAPIView.as_view(permission_classes=[AllowAny], authentication_classes=[]),
        name="schema",
    ),
    path(
        "api/docs/",
        SpectacularSwaggerView.as_view(
            url_name="schema",
            permission_classes=[AllowAny],
            authentication_classes=[],
        ),
        name="swagger-ui",
    ),
    path(
        "api/redoc/",
        SpectacularRedocView.as_view(
            url_name="schema",
            permission_classes=[AllowAny],
            authentication_classes=[],
        ),
        name="redoc",
    ),
]
