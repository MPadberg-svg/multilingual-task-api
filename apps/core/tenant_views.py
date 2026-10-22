"""Views for auth lifecycle (/me/, /logout/), organizations, audit logs, FinOps usage, API keys, webhooks, and live console."""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from django.db.models import Count
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.views import View

from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from apps.core.db_router import use_read_replica
from apps.core.finops import get_org_finops_summary, invalidate_org_budget_cache
from apps.core.middleware import RequestLoggingMiddleware
from apps.core.models import (
    AuditLog,
    Organization,
    OrganizationAPIKey,
    OrganizationMember,
    OrganizationSSOConfig,
    OutboxEvent,
    WebhookDelivery,
    WebhookEndpoint,
)
from apps.core.outbox import replay_dead_letter_outbox_event
from apps.core.pagination import StandardResultsSetPagination
from apps.core.serializers import (
    AuditLogSerializer,
    CurrentUserSerializer,
    LogoutSerializer,
    OIDCTokenExchangeSerializer,
    OrganizationAPIKeyCreateSerializer,
    OrganizationAPIKeySerializer,
    OrganizationFinOpsBudgetSerializer,
    OrganizationMemberCreateSerializer,
    OrganizationMemberSerializer,
    OrganizationSerializer,
    OrganizationSSOConfigSerializer,
    OutboxEventSerializer,
    WebhookDeliverySerializer,
    WebhookEndpointCreateSerializer,
    WebhookEndpointSerializer,
)
from apps.core.sso import (
    SCIMProvisioningError,
    SSOAuthenticationError,
    authenticate_scim_bearer,
    exchange_oidc_token_for_jwt,
    scim_delete_user,
    scim_get_user,
    scim_list_users,
    scim_provision_user,
    scim_update_user,
)
from apps.core.views import get_org_ai_usage
from apps.core.webhooks import deliver_webhook_sync

User = get_user_model()

_ADMIN_ROLES = frozenset({"admin", "owner"})
_ROLE_RANK = {"viewer": 1, "contributor": 2, "admin": 3, "owner": 4}


def _record_audit(
    request: Request,
    *,
    action: str,
    resource_type: str,
    resource_id: str,
    organization: Organization | None = None,
    metadata: dict[str, Any] | None = None,
) -> AuditLog:
    ip_raw = RequestLoggingMiddleware._get_client_ip(request._request)
    ip_val = ip_raw if ip_raw != "unknown" else None
    user_agent = str(request.META.get("HTTP_USER_AGENT", ""))[:500]
    return AuditLog.objects.create(
        organization=organization,
        user=request.user if getattr(request.user, "is_authenticated", False) else None,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=ip_val,
        user_agent=user_agent,
        metadata=metadata or {},
    )


def _get_org_and_role(user: Any, org_id: Any) -> tuple[Organization, str]:
    """Fetch active Organization and caller's membership role or raise 404."""
    organization = get_object_or_404(
        Organization.objects.prefetch_related("members"),
        id=org_id,
        is_active=True,
        members__user_id=user.id,
    )
    membership = OrganizationMember.objects.get(organization=organization, user_id=user.id)
    return organization, membership.role


def _require_org_admin(user: Any, org_id: Any) -> tuple[Organization, str]:
    organization, role = _get_org_and_role(user, org_id)
    if role not in _ADMIN_ROLES:
        raise PermissionDenied("Admin or owner role is required for this organization action.")
    return organization, role


class CurrentUserView(APIView):
    """Retrieve or update the authenticated user's profile and active organizations."""

    permission_classes = [IsAuthenticated]
    serializer_class = CurrentUserSerializer

    def get(self, request: Request) -> Response:
        serializer = CurrentUserSerializer(request.user)
        return Response(serializer.data)

    def patch(self, request: Request) -> Response:
        serializer = CurrentUserSerializer(request.user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


class LogoutView(APIView):
    """Blacklist a SimpleJWT refresh token owned by the authenticated caller."""

    permission_classes = [IsAuthenticated]
    serializer_class = LogoutSerializer

    def post(self, request: Request) -> Response:
        serializer = LogoutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        raw_refresh = str(serializer.validated_data["refresh"])

        try:
            token = RefreshToken(raw_refresh)  # type: ignore[arg-type]
        except TokenError:
            return Response(
                {"error": "Invalid or expired refresh token."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        token_user_id = str(token.get("user_id", ""))
        if token_user_id != str(request.user.id):
            raise PermissionDenied("Refresh token does not belong to the authenticated user.")

        try:
            token.blacklist()
        except TokenError:
            return Response(
                {"error": "Refresh token is already blacklisted."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        _record_audit(
            request,
            action="logout",
            resource_type="User",
            resource_id=str(request.user.id),
        )
        return Response({"status": "logged_out"}, status=status.HTTP_200_OK)


class OrganizationListCreateView(APIView):
    """List caller's organizations or bootstrap a new tenant with caller as owner."""

    permission_classes = [IsAuthenticated]
    serializer_class = OrganizationSerializer

    @extend_schema(responses=OrganizationSerializer(many=True))
    def get(self, request: Request) -> Response:
        orgs = (
            Organization.objects.filter(is_active=True, members__user_id=request.user.id)
            .annotate(member_count_val=Count("members", distinct=True))
            .prefetch_related("members")
            .order_by("-created_at")
        )
        serializer = OrganizationSerializer(orgs, many=True, context={"request": request})
        return Response(serializer.data)

    @transaction.atomic
    def post(self, request: Request) -> Response:
        serializer = OrganizationSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        org: Organization = serializer.save()
        OrganizationMember.objects.create(
            organization=org,
            user=request.user,
            role="owner",
            is_billing_contact=True,
        )
        _record_audit(
            request,
            action="created",
            resource_type="Organization",
            resource_id=str(org.id),
            organization=org,
            metadata={"slug": org.slug},
        )
        refreshed = Organization.objects.prefetch_related("members").get(id=org.id)
        out = OrganizationSerializer(refreshed, context={"request": request}).data
        return Response(out, status=status.HTTP_201_CREATED)


class OrganizationDetailView(APIView):
    """Retrieve or update an organization's metadata."""

    permission_classes = [IsAuthenticated]
    serializer_class = OrganizationSerializer

    def get(self, request: Request, org_id: str) -> Response:
        org, _role = _get_org_and_role(request.user, org_id)
        return Response(OrganizationSerializer(org, context={"request": request}).data)

    def patch(self, request: Request, org_id: str) -> Response:
        org, _role = _require_org_admin(request.user, org_id)
        serializer = OrganizationSerializer(
            org, data=request.data, partial=True, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        _record_audit(
            request,
            action="updated",
            resource_type="Organization",
            resource_id=str(org.id),
            organization=org,
        )
        return Response(serializer.data)


class OrganizationMemberListCreateView(APIView):
    """List organization members or add an active user enforcing seat quotas and RBAC."""

    permission_classes = [IsAuthenticated]
    serializer_class = OrganizationMemberSerializer

    @extend_schema(responses=OrganizationMemberSerializer(many=True))
    def get(self, request: Request, org_id: str) -> Response:
        org, _role = _get_org_and_role(request.user, org_id)
        members = org.members.select_related("user").order_by("joined_at")
        return Response(OrganizationMemberSerializer(members, many=True).data)

    @transaction.atomic
    def post(self, request: Request, org_id: str) -> Response:
        org, actor_role = _require_org_admin(request.user, org_id)
        serializer = OrganizationMemberCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        target_email = str(serializer.validated_data["email"]).strip().lower()
        target_role = str(serializer.validated_data["role"])

        if target_role == "owner" and actor_role != "owner":
            raise PermissionDenied("Only an organization owner can grant the owner role.")

        target_user = User.objects.filter(email__iexact=target_email, is_active=True).first()
        if target_user is None:
            return Response(
                {"error": "No active user found with that email address."},
                status=status.HTTP_404_NOT_FOUND,
            )

        if OrganizationMember.objects.filter(organization=org, user=target_user).exists():
            return Response(
                {"error": "User is already a member of this organization."},
                status=status.HTTP_409_CONFLICT,
            )

        try:
            member = OrganizationMember.objects.create(
                organization=org,
                user=target_user,
                role=target_role,
            )
        except DjangoValidationError as exc:
            return Response(
                {"error": exc.messages[0] if exc.messages else str(exc)},
                status=status.HTTP_403_FORBIDDEN,
            )

        _record_audit(
            request,
            action="permission_changed",
            resource_type="OrganizationMember",
            resource_id=str(member.id),
            organization=org,
            metadata={"target_user": str(target_user.id), "role": target_role},
        )
        return Response(
            OrganizationMemberSerializer(member).data,
            status=status.HTTP_201_CREATED,
        )


class OrganizationMemberDetailView(APIView):
    """Update a member's role or remove them while protecting the last owner."""

    permission_classes = [IsAuthenticated]
    serializer_class = OrganizationMemberSerializer

    @transaction.atomic
    def patch(self, request: Request, org_id: str, member_id: str) -> Response:
        org, actor_role = _require_org_admin(request.user, org_id)
        member = get_object_or_404(
            OrganizationMember.objects.select_related("user"),
            id=member_id,
            organization=org,
        )

        new_role = str(request.data.get("role", member.role))
        if new_role not in _ROLE_RANK:
            return Response(
                {"error": f"Invalid role '{new_role}'."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if (member.role == "owner" or new_role == "owner") and actor_role != "owner":
            raise PermissionDenied("Only an organization owner can modify owner memberships.")

        if member.role == "owner" and new_role != "owner":
            owner_count = OrganizationMember.objects.filter(organization=org, role="owner").count()
            if owner_count <= 1:
                return Response(
                    {"error": "Cannot demote the last owner of an organization."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        member.role = new_role
        member.save(update_fields=["role"])
        _record_audit(
            request,
            action="permission_changed",
            resource_type="OrganizationMember",
            resource_id=str(member.id),
            organization=org,
            metadata={"new_role": new_role},
        )
        return Response(OrganizationMemberSerializer(member).data)

    @transaction.atomic
    def delete(self, request: Request, org_id: str, member_id: str) -> Response:
        org, actor_role = _require_org_admin(request.user, org_id)
        member = get_object_or_404(OrganizationMember, id=member_id, organization=org)

        if member.role == "owner" and actor_role != "owner":
            raise PermissionDenied("Only an organization owner can remove another owner.")

        if member.role == "owner":
            owner_count = OrganizationMember.objects.filter(organization=org, role="owner").count()
            if owner_count <= 1:
                return Response(
                    {"error": "Cannot remove the last owner of an organization."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        removed_id = str(member.id)
        member.delete()
        _record_audit(
            request,
            action="deleted",
            resource_type="OrganizationMember",
            resource_id=removed_id,
            organization=org,
        )
        return Response(status=status.HTTP_204_NO_CONTENT)


class OrganizationAuditLogListView(APIView):
    """Paginated, filterable security audit trail for organization admins/owners."""

    permission_classes = [IsAuthenticated]
    serializer_class = AuditLogSerializer

    def get(self, request: Request, org_id: str) -> Response:
        org, _role = _require_org_admin(request.user, org_id)
        qs = AuditLog.objects.filter(organization=org).select_related("user")

        action_filter = request.query_params.get("action", "").strip()
        if action_filter:
            qs = qs.filter(action=action_filter)

        resource_filter = request.query_params.get("resource_type", "").strip()
        if resource_filter:
            qs = qs.filter(resource_type=resource_filter)

        paginator = StandardResultsSetPagination()
        page = paginator.paginate_queryset(qs, request, view=self)
        serializer = AuditLogSerializer(page, many=True)
        return paginator.get_paginated_response(serializer.data)


class OrganizationUsageView(APIView):
    """Real-time tenant plan quota and OpenAI token/cost FinOps telemetry."""

    permission_classes = [IsAuthenticated]
    serializer_class = OrganizationSerializer

    def get(self, request: Request, org_id: str) -> Response:
        with use_read_replica() as query_target:
            org, _role = _get_org_and_role(request.user, org_id)
            seat_used = OrganizationMember.objects.filter(organization_id=org.id).count()
            tasks_used = org.tasks.filter(is_active=True).count()
        ai_usage = get_org_ai_usage(str(org.id))

        return Response(
            {
                "organization_id": str(org.id),
                "plan": org.plan,
                "quotas": {
                    "users": {"used": seat_used, "limit": org.max_users},
                    "tasks": {"used": tasks_used, "limit": org.max_tasks},
                    "ai_requests_daily": {
                        "used": ai_usage["requests_daily"],
                        "limit": org.max_ai_requests,
                    },
                },
                "ai_telemetry": {
                    "requests_total": ai_usage["requests_total"],
                    "prompt_tokens_total": ai_usage["prompt_tokens"],
                    "completion_tokens_total": ai_usage["completion_tokens"],
                    "estimated_cost_usd": ai_usage["estimated_cost_usd"],
                },
            },
            headers={"X-Query-Target": query_target},
        )


class OrganizationFinOpsView(APIView):
    """Monthly AI token/USD budget governance and read-replica FinOps analytics."""

    permission_classes = [IsAuthenticated]
    serializer_class = OrganizationFinOpsBudgetSerializer

    @extend_schema(responses={200: {"type": "object"}})
    def get(self, request: Request, org_id: str) -> Response:
        with use_read_replica():
            org, _role = _get_org_and_role(request.user, org_id)
        period_param = (request.query_params.get("billing_period") or "").strip() or None
        summary, query_target = get_org_finops_summary(org, billing_period=period_param)
        return Response(summary, headers={"X-Query-Target": query_target})

    @extend_schema(
        request=OrganizationFinOpsBudgetSerializer,
        responses={200: {"type": "object"}},
    )
    @transaction.atomic
    def patch(self, request: Request, org_id: str) -> Response:
        org, _role = _require_org_admin(request.user, org_id)
        serializer = OrganizationFinOpsBudgetSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)

        updated_fields: list[str] = []
        for field_name in (
            "monthly_ai_token_budget",
            "monthly_ai_cost_budget_microusd",
            "ai_budget_alert_threshold_pct",
        ):
            if field_name in serializer.validated_data:
                setattr(org, field_name, int(serializer.validated_data[field_name]))
                updated_fields.append(field_name)

        if updated_fields:
            org.save(update_fields=updated_fields)
            invalidate_org_budget_cache(str(org.id))
            _record_audit(
                request,
                action="finops_budget_updated",
                resource_type="Organization",
                resource_id=str(org.id),
                organization=org,
                metadata={f: getattr(org, f) for f in updated_fields},
            )

        summary, query_target = get_org_finops_summary(org)
        return Response(summary, headers={"X-Query-Target": query_target})


class OrganizationAPIKeyListCreateView(APIView):
    """List or mint SHA-256-hashed scoped M2M API keys for an organization."""

    permission_classes = [IsAuthenticated]
    serializer_class = OrganizationAPIKeySerializer

    @extend_schema(responses=OrganizationAPIKeySerializer(many=True))
    def get(self, request: Request, org_id: str) -> Response:
        org, _role = _require_org_admin(request.user, org_id)
        keys = org.api_keys.all()
        return Response(OrganizationAPIKeySerializer(keys, many=True).data)

    @transaction.atomic
    def post(self, request: Request, org_id: str) -> Response:
        org, actor_role = _require_org_admin(request.user, org_id)
        serializer = OrganizationAPIKeyCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        requested_role = str(serializer.validated_data["role"])
        if _ROLE_RANK[requested_role] > _ROLE_RANK[actor_role]:
            raise PermissionDenied("API key role cannot exceed the creator's role.")

        key_obj, raw_key = OrganizationAPIKey.create_with_raw_key(
            organization=org,
            created_by=request.user,
            name=str(serializer.validated_data["name"]),
            role=requested_role,
            scopes=list(serializer.validated_data["scopes"]),
            expires_at=serializer.validated_data["expires_at"],
        )
        _record_audit(
            request,
            action="api_key_created",
            resource_type="OrganizationAPIKey",
            resource_id=str(key_obj.id),
            organization=org,
            metadata={"prefix": key_obj.prefix, "role": key_obj.role, "scopes": key_obj.scopes},
        )
        payload = dict(OrganizationAPIKeySerializer(key_obj).data)
        payload["api_key"] = raw_key
        return Response(payload, status=status.HTTP_201_CREATED)


class OrganizationAPIKeyDetailView(APIView):
    """Revoke an organization API key immediately."""

    permission_classes = [IsAuthenticated]
    serializer_class = OrganizationAPIKeySerializer

    @transaction.atomic
    def delete(self, request: Request, org_id: str, key_id: str) -> Response:
        org, _role = _require_org_admin(request.user, org_id)
        key_obj = get_object_or_404(OrganizationAPIKey, id=key_id, organization=org)
        if key_obj.revoked_at is None:
            key_obj.revoked_at = timezone.now()
            key_obj.save(update_fields=["revoked_at"])
            _record_audit(
                request,
                action="api_key_revoked",
                resource_type="OrganizationAPIKey",
                resource_id=str(key_obj.id),
                organization=org,
                metadata={"prefix": key_obj.prefix},
            )
        return Response(status=status.HTTP_204_NO_CONTENT)


class OrganizationWebhookListCreateView(APIView):
    """List or register SSRF-validated, HMAC-SHA256-signed webhook endpoints."""

    permission_classes = [IsAuthenticated]
    serializer_class = WebhookEndpointSerializer

    @extend_schema(responses=WebhookEndpointSerializer(many=True))
    def get(self, request: Request, org_id: str) -> Response:
        org, _role = _require_org_admin(request.user, org_id)
        endpoints = org.webhooks.all()
        return Response(WebhookEndpointSerializer(endpoints, many=True).data)

    @transaction.atomic
    def post(self, request: Request, org_id: str) -> Response:
        org, _role = _require_org_admin(request.user, org_id)
        serializer = WebhookEndpointCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        signing_secret = f"whsec_{secrets.token_hex(24)}"
        endpoint = WebhookEndpoint.objects.create(
            organization=org,
            created_by=request.user,
            url=str(serializer.validated_data["url"]),
            description=str(serializer.validated_data["description"]),
            secret=signing_secret,
            events=list(serializer.validated_data["events"]),
        )
        _record_audit(
            request,
            action="webhook_created",
            resource_type="WebhookEndpoint",
            resource_id=str(endpoint.id),
            organization=org,
            metadata={"url": endpoint.url, "events": endpoint.events},
        )
        data = dict(WebhookEndpointSerializer(endpoint).data)
        # Signing secret is revealed once upon creation
        data["signing_secret"] = signing_secret
        return Response(data, status=status.HTTP_201_CREATED)


class OrganizationWebhookDetailView(APIView):
    """Delete a webhook endpoint."""

    permission_classes = [IsAuthenticated]
    serializer_class = WebhookEndpointSerializer

    @transaction.atomic
    def delete(self, request: Request, org_id: str, webhook_id: str) -> Response:
        org, _role = _require_org_admin(request.user, org_id)
        endpoint = get_object_or_404(WebhookEndpoint, id=webhook_id, organization=org)
        ep_id = str(endpoint.id)
        endpoint.delete()
        _record_audit(
            request,
            action="webhook_deleted",
            resource_type="WebhookEndpoint",
            resource_id=ep_id,
            organization=org,
        )
        return Response(status=status.HTTP_204_NO_CONTENT)


class OrganizationWebhookTestView(APIView):
    """Send a signed ``webhook.ping`` test event and return the delivery record."""

    permission_classes = [IsAuthenticated]
    serializer_class = WebhookDeliverySerializer

    def post(self, request: Request, org_id: str, webhook_id: str) -> Response:
        org, _role = _require_org_admin(request.user, org_id)
        endpoint = get_object_or_404(WebhookEndpoint, id=webhook_id, organization=org)
        delivery = deliver_webhook_sync(
            endpoint,
            "webhook.ping",
            {"message": "Test ping from Multilingual Task API", "organization_id": str(org.id)},
        )
        return Response(WebhookDeliverySerializer(delivery).data, status=status.HTTP_200_OK)


class OrganizationWebhookRecoverView(APIView):
    """Reset consecutive failure counter and re-enable a circuit-broken webhook endpoint."""

    permission_classes = [IsAuthenticated]
    serializer_class = WebhookEndpointSerializer

    @transaction.atomic
    def post(self, request: Request, org_id: str, webhook_id: str) -> Response:
        org, _role = _require_org_admin(request.user, org_id)
        endpoint = get_object_or_404(WebhookEndpoint, id=webhook_id, organization=org)
        prev_failures = int(endpoint.failure_count)
        prev_active = bool(endpoint.is_active)

        endpoint.failure_count = 0
        endpoint.is_active = True
        endpoint.save(update_fields=["failure_count", "is_active"])

        _record_audit(
            request,
            action="webhook_recovered",
            resource_type="WebhookEndpoint",
            resource_id=str(endpoint.id),
            organization=org,
            metadata={
                "previous_failures": prev_failures,
                "was_active": prev_active,
            },
        )
        return Response(WebhookEndpointSerializer(endpoint).data, status=status.HTTP_200_OK)


class OrganizationWebhookDeliveryListView(APIView):
    """Paginated delivery history for a tenant webhook endpoint."""

    permission_classes = [IsAuthenticated]
    serializer_class = WebhookDeliverySerializer

    def get(self, request: Request, org_id: str, webhook_id: str) -> Response:
        org, _role = _require_org_admin(request.user, org_id)
        endpoint = get_object_or_404(WebhookEndpoint, id=webhook_id, organization=org)
        qs = WebhookDelivery.objects.filter(endpoint=endpoint).order_by("-delivered_at")

        success_param = request.query_params.get("success", "").strip().lower()
        if success_param in {"true", "1"}:
            qs = qs.filter(success=True)
        elif success_param in {"false", "0"}:
            qs = qs.filter(success=False)

        event_filter = request.query_params.get("event_type", "").strip()
        if event_filter:
            qs = qs.filter(event_type=event_filter)

        paginator = StandardResultsSetPagination()
        page = paginator.paginate_queryset(qs, request, view=self)
        serializer = WebhookDeliverySerializer(page, many=True)
        return paginator.get_paginated_response(serializer.data)


class OrganizationWebhookDeliveryReplayView(APIView):
    """Replay a historical or failed webhook delivery with fresh HMAC timestamp & signature."""

    permission_classes = [IsAuthenticated]
    serializer_class = WebhookDeliverySerializer

    def post(
        self,
        request: Request,
        org_id: str,
        webhook_id: str,
        delivery_id: str,
    ) -> Response:
        org, _role = _require_org_admin(request.user, org_id)
        endpoint = get_object_or_404(WebhookEndpoint, id=webhook_id, organization=org)
        source_delivery = get_object_or_404(
            WebhookDelivery,
            id=delivery_id,
            endpoint=endpoint,
        )
        raw_envelope = source_delivery.payload if isinstance(source_delivery.payload, dict) else {}
        inner_data = raw_envelope.get("data")
        event_data = dict(inner_data) if isinstance(inner_data, dict) else {}

        new_delivery = deliver_webhook_sync(
            endpoint,
            source_delivery.event_type,
            event_data,
        )
        _record_audit(
            request,
            action="webhook_replayed",
            resource_type="WebhookDelivery",
            resource_id=str(new_delivery.id),
            organization=org,
            metadata={
                "source_delivery_id": str(source_delivery.id),
                "webhook_id": str(endpoint.id),
                "event_type": source_delivery.event_type,
                "success": new_delivery.success,
            },
        )
        return Response(WebhookDeliverySerializer(new_delivery).data, status=status.HTTP_200_OK)


class OrganizationOutboxListView(APIView):
    """Paginated tenant Transactional Outbox inspector (filterable by status and topic)."""

    permission_classes = [IsAuthenticated]
    serializer_class = OutboxEventSerializer

    def get(self, request: Request, org_id: str) -> Response:
        org, _role = _require_org_admin(request.user, org_id)
        qs = OutboxEvent.objects.filter(organization=org).order_by("-created_at")

        status_filter = request.query_params.get("status", "").strip()
        if status_filter:
            qs = qs.filter(status=status_filter)

        topic_filter = request.query_params.get("topic", "").strip()
        if topic_filter:
            qs = qs.filter(topic=topic_filter)

        paginator = StandardResultsSetPagination()
        page = paginator.paginate_queryset(qs, request, view=self)
        serializer = OutboxEventSerializer(page, many=True)
        return paginator.get_paginated_response(serializer.data)


class OrganizationOutboxReplayView(APIView):
    """Replay a ``failed`` dead-letter Transactional Outbox event for immediate relay."""

    permission_classes = [IsAuthenticated]
    serializer_class = OutboxEventSerializer

    def post(self, request: Request, org_id: str, event_id: str) -> Response:
        org, _role = _require_org_admin(request.user, org_id)
        event = get_object_or_404(OutboxEvent, id=event_id, organization=org)
        try:
            replayed = replay_dead_letter_outbox_event(event)
        except ValueError as exc:
            return Response({"error": str(exc)}, status=status.HTTP_409_CONFLICT)

        _record_audit(
            request,
            action="outbox_replayed",
            resource_type="OutboxEvent",
            resource_id=str(replayed.id),
            organization=org,
            metadata={"event_type": replayed.event_type, "topic": replayed.topic},
        )
        replayed.refresh_from_db()
        return Response(OutboxEventSerializer(replayed).data, status=status.HTTP_200_OK)


class OrganizationSSOConfigView(APIView):
    """Inspect or configure enterprise OIDC SSO & SCIM 2.0 provisioning for an organization."""

    permission_classes = [IsAuthenticated]
    serializer_class = OrganizationSSOConfigSerializer

    def get(self, request: Request, org_id: str) -> Response:
        org, _role = _require_org_admin(request.user, org_id)
        sso_config, _ = OrganizationSSOConfig.objects.get_or_create(organization=org)
        return Response(OrganizationSSOConfigSerializer(sso_config).data)

    @transaction.atomic
    def patch(self, request: Request, org_id: str) -> Response:
        org, _role = _require_org_admin(request.user, org_id)
        sso_config, _ = OrganizationSSOConfig.objects.get_or_create(organization=org)
        serializer = OrganizationSSOConfigSerializer(
            sso_config,
            data=request.data,
            partial=True,
        )
        serializer.is_valid(raise_exception=True)
        updated = serializer.save()
        _record_audit(
            request,
            action="sso_updated",
            resource_type="OrganizationSSOConfig",
            resource_id=str(updated.id),
            organization=org,
            metadata={
                "enabled": updated.enabled,
                "oidc_issuer": updated.oidc_issuer,
                "scim_enabled": updated.scim_enabled,
                "jit_provisioning": updated.jit_provisioning,
            },
        )
        return Response(OrganizationSSOConfigSerializer(updated).data)


class OrganizationSCIMTokenRotateView(APIView):
    """Mint or rotate the organization's SHA-256-hashed RFC 7644 SCIM 2.0 Bearer credential."""

    permission_classes = [IsAuthenticated]
    serializer_class = OrganizationSSOConfigSerializer

    @extend_schema(request=None, responses={201: {"type": "object"}})
    @transaction.atomic
    def post(self, request: Request, org_id: str) -> Response:
        org, _role = _require_org_admin(request.user, org_id)
        sso_config, _ = OrganizationSSOConfig.objects.get_or_create(organization=org)
        raw_token = sso_config.rotate_scim_token()
        _record_audit(
            request,
            action="scim_token_rotated",
            resource_type="OrganizationSSOConfig",
            resource_id=str(sso_config.id),
            organization=org,
            metadata={"scim_token_prefix": sso_config.scim_token_prefix},
        )
        return Response(
            {
                "organization_id": str(org.id),
                "scim_enabled": sso_config.scim_enabled,
                "scim_token_prefix": sso_config.scim_token_prefix,
                "scim_token": raw_token,
            },
            status=status.HTTP_201_CREATED,
        )


class OIDCTokenExchangeView(APIView):
    """Exchange an enterprise IdP OIDC ``id_token`` for local SimpleJWT session credentials."""

    authentication_classes: list[Any] = []
    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]
    serializer_class = OIDCTokenExchangeSerializer

    @extend_schema(
        request=OIDCTokenExchangeSerializer,
        responses={200: {"type": "object"}, 401: {"type": "object"}, 403: {"type": "object"}},
    )
    def post(self, request: Request) -> Response:
        serializer = OIDCTokenExchangeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        ip_raw = RequestLoggingMiddleware._get_client_ip(request._request)
        ip_val = ip_raw if ip_raw != "unknown" else None
        user_agent = str(request.META.get("HTTP_USER_AGENT", ""))[:500]

        try:
            payload = exchange_oidc_token_for_jwt(
                organization_slug=str(serializer.validated_data["organization_slug"]),
                raw_id_token=str(serializer.validated_data["id_token"]),
                ip_address=ip_val,
                user_agent=user_agent,
            )
        except SSOAuthenticationError as exc:
            return Response({"error": str(exc)}, status=exc.status_code)

        return Response(payload, status=status.HTTP_200_OK)


def _client_meta(request: Request) -> tuple[str | None, str]:
    ip_raw = RequestLoggingMiddleware._get_client_ip(request._request)
    ip_val = ip_raw if ip_raw != "unknown" else None
    user_agent = str(request.META.get("HTTP_USER_AGENT", ""))[:500]
    return ip_val, user_agent


class OrganizationSCIMUsersView(APIView):
    """RFC 7643/7644 SCIM 2.0 ``/scim/v2/Users`` directory list and user provisioning endpoint."""

    authentication_classes: list[Any] = []
    permission_classes = [AllowAny]
    throttle_classes: list[Any] = []

    @extend_schema(
        operation_id="v1_organizations_scim_v2_users_list",
        responses={200: {"type": "object"}, 401: {"type": "object"}},
    )
    def get(self, request: Request, org_id: str) -> Response:
        try:
            org, _sso_config = authenticate_scim_bearer(request, org_id)
            raw_start = request.query_params.get("startIndex", "1")
            raw_count = request.query_params.get("count", "100")
            start_idx = int(raw_start) if str(raw_start).isdigit() else 1
            count_val = int(raw_count) if str(raw_count).isdigit() else 100
            result = scim_list_users(
                org=org,
                filter_expr=str(request.query_params.get("filter") or ""),
                start_index=start_idx,
                count=count_val,
            )
            return Response(result, content_type="application/scim+json")
        except SCIMProvisioningError as exc:
            return Response(
                exc.as_scim_payload(),
                status=exc.status_code,
                content_type="application/scim+json",
            )

    @extend_schema(
        operation_id="v1_organizations_scim_v2_users_create",
        request={"application/json": {"type": "object"}},
        responses={201: {"type": "object"}, 200: {"type": "object"}},
    )
    def post(self, request: Request, org_id: str) -> Response:
        try:
            org, sso_config = authenticate_scim_bearer(request, org_id)
            if not isinstance(request.data, dict):
                raise SCIMProvisioningError(
                    "SCIM request body must be a JSON object.",
                    status_code=400,
                    scim_type="invalidSyntax",
                )
            ip_val, ua = _client_meta(request)
            resource, created = scim_provision_user(
                org=org,
                sso_config=sso_config,
                payload=request.data,
                ip_address=ip_val,
                user_agent=ua,
            )
            http_status = status.HTTP_201_CREATED if created else status.HTTP_200_OK
            return Response(
                resource,
                status=http_status,
                content_type="application/scim+json",
            )
        except SCIMProvisioningError as exc:
            return Response(
                exc.as_scim_payload(),
                status=exc.status_code,
                content_type="application/scim+json",
            )


class OrganizationSCIMUserDetailView(APIView):
    """RFC 7643/7644 SCIM 2.0 ``/scim/v2/Users/<member_id>`` retrieve, update, and offboarding."""

    authentication_classes: list[Any] = []
    permission_classes = [AllowAny]
    throttle_classes: list[Any] = []

    @extend_schema(
        operation_id="v1_organizations_scim_v2_users_retrieve",
        responses={200: {"type": "object"}, 404: {"type": "object"}},
    )
    def get(self, request: Request, org_id: str, member_id: str) -> Response:
        try:
            org, _sso_config = authenticate_scim_bearer(request, org_id)
            resource = scim_get_user(org=org, member_id=str(member_id))
            return Response(resource, content_type="application/scim+json")
        except SCIMProvisioningError as exc:
            return Response(
                exc.as_scim_payload(),
                status=exc.status_code,
                content_type="application/scim+json",
            )

    @extend_schema(
        request={"application/json": {"type": "object"}},
        responses={200: {"type": "object"}},
    )
    def put(self, request: Request, org_id: str, member_id: str) -> Response:
        return self._modify(request, org_id=org_id, member_id=str(member_id), is_patch=False)

    @extend_schema(
        request={"application/json": {"type": "object"}},
        responses={200: {"type": "object"}},
    )
    def patch(self, request: Request, org_id: str, member_id: str) -> Response:
        return self._modify(request, org_id=org_id, member_id=str(member_id), is_patch=True)

    def _modify(
        self,
        request: Request,
        *,
        org_id: str,
        member_id: str,
        is_patch: bool,
    ) -> Response:
        try:
            org, sso_config = authenticate_scim_bearer(request, org_id)
            if not isinstance(request.data, dict):
                raise SCIMProvisioningError(
                    "SCIM request body must be a JSON object.",
                    status_code=400,
                    scim_type="invalidSyntax",
                )
            ip_val, ua = _client_meta(request)
            resource = scim_update_user(
                org=org,
                sso_config=sso_config,
                member_id=member_id,
                payload=request.data,
                is_patch=is_patch,
                ip_address=ip_val,
                user_agent=ua,
            )
            return Response(
                resource, status=status.HTTP_200_OK, content_type="application/scim+json"
            )
        except SCIMProvisioningError as exc:
            return Response(
                exc.as_scim_payload(),
                status=exc.status_code,
                content_type="application/scim+json",
            )

    @extend_schema(responses={204: None, 404: {"type": "object"}})
    def delete(self, request: Request, org_id: str, member_id: str) -> Response:
        try:
            org, _sso_config = authenticate_scim_bearer(request, org_id)
            ip_val, ua = _client_meta(request)
            scim_delete_user(
                org=org,
                member_id=str(member_id),
                ip_address=ip_val,
                user_agent=ua,
            )
            return Response(status=status.HTTP_204_NO_CONTENT)
        except SCIMProvisioningError as exc:
            return Response(
                exc.as_scim_payload(),
                status=exc.status_code,
                content_type="application/scim+json",
            )


class ExplorerConsoleView(View):
    """Serve the interactive API & live WebSocket operations console with a strict CSP nonce."""

    def get(self, request: HttpRequest) -> HttpResponse:
        nonce = secrets.token_urlsafe(24)
        setattr(request, "_csp_nonce", nonce)
        html_path: Path = settings.BASE_DIR / "docs" / "api-explorer.html"
        raw_html = html_path.read_text(encoding="utf-8")
        rendered = raw_html.replace("<style>", f'<style nonce="{nonce}">', 1).replace(
            "<script>", f'<script nonce="{nonce}">', 1
        )
        return HttpResponse(rendered, content_type="text/html; charset=utf-8")
