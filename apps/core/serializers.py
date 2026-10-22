"""Serializers for auth lifecycle, self-serve multi-tenancy, API keys, webhooks, and audit logs."""

from __future__ import annotations

from typing import Any

from django.contrib.auth import get_user_model

from rest_framework import serializers

from apps.core.models import (
    VALID_API_KEY_SCOPES,
    VALID_WEBHOOK_EVENTS,
    AuditLog,
    Organization,
    OrganizationAPIKey,
    OrganizationMember,
    OutboxEvent,
    WebhookDelivery,
    WebhookEndpoint,
)
from apps.core.security import InputValidator
from apps.core.webhooks import validate_webhook_url

User = get_user_model()


def _clean_plain_text(value: str, label: str, max_length: int) -> str:
    is_bad, reason = InputValidator.detect_injection(value)
    if is_bad:
        raise serializers.ValidationError(f"Invalid {label}: {reason}")
    try:
        return InputValidator.sanitize_string(value, max_length=max_length)
    except ValueError as exc:
        raise serializers.ValidationError(str(exc)) from exc


class UserOrganizationSummarySerializer(serializers.ModelSerializer):
    """Compact summary of a user's active organization membership."""

    organization_id = serializers.UUIDField(source="organization.id", read_only=True)
    name = serializers.CharField(source="organization.name", read_only=True)
    slug = serializers.SlugField(source="organization.slug", read_only=True)
    plan = serializers.CharField(source="organization.plan", read_only=True)

    class Meta:
        model = OrganizationMember
        fields = ["organization_id", "name", "slug", "plan", "role", "joined_at"]


class CurrentUserSerializer(serializers.ModelSerializer):
    """Profile serializer for ``/api/v1/auth/me/``."""

    organizations = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "first_name",
            "last_name",
            "is_staff",
            "date_joined",
            "organizations",
        ]
        read_only_fields = ["id", "email", "is_staff", "date_joined", "organizations"]

    def validate_first_name(self, value: str) -> str:
        return _clean_plain_text(value, "first_name", max_length=150)

    def validate_last_name(self, value: str) -> str:
        return _clean_plain_text(value, "last_name", max_length=150)

    def get_organizations(self, obj: Any) -> list[dict[str, Any]]:
        memberships = obj.organization_memberships.select_related("organization").filter(
            organization__is_active=True
        )
        return list(UserOrganizationSummarySerializer(memberships, many=True).data)


class LogoutSerializer(serializers.Serializer):
    """Payload for ``POST /api/v1/auth/logout/``."""

    refresh = serializers.CharField(required=True, allow_blank=False)


class OrganizationSerializer(serializers.ModelSerializer):
    """Serializer for creating, reading, and updating tenant Organizations."""

    member_count = serializers.SerializerMethodField()
    my_role = serializers.SerializerMethodField()

    class Meta:
        model = Organization
        fields = [
            "id",
            "name",
            "slug",
            "plan",
            "max_users",
            "max_tasks",
            "max_ai_requests",
            "member_count",
            "my_role",
            "is_active",
            "created_at",
        ]
        read_only_fields = [
            "id",
            "plan",
            "max_users",
            "max_tasks",
            "max_ai_requests",
            "member_count",
            "my_role",
            "is_active",
            "created_at",
        ]

    def validate_name(self, value: str) -> str:
        cleaned = _clean_plain_text(value, "name", max_length=255)
        if not cleaned:
            raise serializers.ValidationError("Organization name cannot be empty.")
        return cleaned

    def get_member_count(self, obj: Organization) -> int:
        annotated = getattr(obj, "member_count_val", None)
        if isinstance(annotated, int):
            return annotated
        return int(obj.members.count())

    def get_my_role(self, obj: Organization) -> str | None:
        request = self.context.get("request")
        if request is None or not getattr(request.user, "is_authenticated", False):
            return None
        for membership in obj.members.all():
            if membership.user_id == request.user.id:
                return str(membership.role)
        return None


class OrganizationMemberSerializer(serializers.ModelSerializer):
    """Read/update representation of an OrganizationMember."""

    email = serializers.EmailField(source="user.email", read_only=True)
    user_id = serializers.UUIDField(source="user.id", read_only=True)

    class Meta:
        model = OrganizationMember
        fields = ["id", "user_id", "email", "role", "is_billing_contact", "joined_at"]
        read_only_fields = ["id", "user_id", "email", "joined_at"]


class OrganizationMemberCreateSerializer(serializers.Serializer):
    """Payload to add an existing active user to an Organization."""

    email = serializers.EmailField(required=True)
    role = serializers.ChoiceField(
        choices=["viewer", "contributor", "admin", "owner"],
        default="viewer",
    )


class AuditLogSerializer(serializers.ModelSerializer):
    """Read-only representation of immutable security AuditLog records."""

    user_email = serializers.EmailField(source="user.email", read_only=True, default=None)

    class Meta:
        model = AuditLog
        fields = [
            "id",
            "organization",
            "user",
            "user_email",
            "action",
            "resource_type",
            "resource_id",
            "ip_address",
            "user_agent",
            "metadata",
            "created_at",
        ]
        read_only_fields = fields


class OrganizationAPIKeySerializer(serializers.ModelSerializer):
    """Safe read-only representation of an API key (never exposes hashed_key)."""

    is_usable = serializers.BooleanField(read_only=True)

    class Meta:
        model = OrganizationAPIKey
        fields = [
            "id",
            "name",
            "prefix",
            "role",
            "scopes",
            "is_usable",
            "expires_at",
            "revoked_at",
            "last_used_at",
            "created_at",
        ]
        read_only_fields = fields


class OrganizationAPIKeyCreateSerializer(serializers.Serializer):
    """Payload to mint a new scoped M2M API key."""

    name = serializers.CharField(max_length=100)
    role = serializers.ChoiceField(
        choices=["viewer", "contributor", "admin"],
        default="contributor",
    )
    scopes = serializers.ListField(
        child=serializers.CharField(max_length=40),
        required=False,
        default=lambda: sorted(VALID_API_KEY_SCOPES),
    )
    expires_at = serializers.DateTimeField(required=False, allow_null=True, default=None)

    def validate_name(self, value: str) -> str:
        cleaned = _clean_plain_text(value, "name", max_length=100)
        if not cleaned:
            raise serializers.ValidationError("API key name cannot be empty.")
        return cleaned

    def validate_scopes(self, value: list[str]) -> list[str]:
        if not value:
            raise serializers.ValidationError("At least one scope must be specified.")
        invalid = [s for s in value if s not in VALID_API_KEY_SCOPES]
        if invalid:
            raise serializers.ValidationError(
                f"Invalid scopes {invalid}. Allowed: {sorted(VALID_API_KEY_SCOPES)}."
            )
        return sorted(set(value))


class WebhookEndpointSerializer(serializers.ModelSerializer):
    """Safe read-only representation of a WebhookEndpoint (secret masked)."""

    secret_preview = serializers.SerializerMethodField()

    class Meta:
        model = WebhookEndpoint
        fields = [
            "id",
            "url",
            "description",
            "events",
            "is_active",
            "failure_count",
            "secret_preview",
            "last_triggered_at",
            "created_at",
        ]
        read_only_fields = fields

    def get_secret_preview(self, obj: WebhookEndpoint) -> str:
        return f"{obj.secret[:6]}...{obj.secret[-4:]}" if len(obj.secret) >= 12 else "****"


class WebhookEndpointCreateSerializer(serializers.Serializer):
    """Validated payload to register an SSRF-safe outbound WebhookEndpoint."""

    url = serializers.URLField(max_length=500)
    description = serializers.CharField(
        max_length=255, required=False, allow_blank=True, default=""
    )
    events = serializers.ListField(
        child=serializers.CharField(max_length=50),
        required=False,
        default=lambda: ["task.completed", "task.consensus_reached"],
    )

    def validate_url(self, value: str) -> str:
        try:
            return validate_webhook_url(value, resolve_dns=False)
        except ValueError as exc:
            raise serializers.ValidationError(str(exc)) from exc

    def validate_description(self, value: str) -> str:
        return _clean_plain_text(value, "description", max_length=255)

    def validate_events(self, value: list[str]) -> list[str]:
        if not value:
            raise serializers.ValidationError("At least one webhook event must be selected.")
        invalid = [ev for ev in value if ev not in VALID_WEBHOOK_EVENTS]
        if invalid:
            raise serializers.ValidationError(
                f"Unsupported events {invalid}. Supported: {sorted(VALID_WEBHOOK_EVENTS)}."
            )
        return sorted(set(value))


class WebhookDeliverySerializer(serializers.ModelSerializer):
    """Read-only representation of a webhook delivery attempt."""

    class Meta:
        model = WebhookDelivery
        fields = [
            "id",
            "endpoint",
            "event_type",
            "response_status",
            "success",
            "error_message",
            "delivered_at",
        ]
        read_only_fields = fields


class OutboxEventSerializer(serializers.ModelSerializer):
    """Read-only representation of a tenant Transactional Outbox event."""

    class Meta:
        model = OutboxEvent
        fields = [
            "id",
            "organization",
            "topic",
            "event_type",
            "payload",
            "traceparent",
            "status",
            "attempts",
            "next_attempt_at",
            "dispatched_at",
            "last_error",
            "created_at",
        ]
        read_only_fields = fields
