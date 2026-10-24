"""Multi-tenancy, M2M API keys, outbound webhooks, and audit models for the core app.

Provides:
    - ``CustomUser``: UUID-indexed, email-authenticated user model.
    - ``Organization``: Tenant container with plan-based limits.
    - ``OrganizationMember``: RBAC membership linking users to orgs.
    - ``OrganizationAPIKey``: Prefix-indexed, SHA-256-hashed scoped M2M API keys.
    - ``WebhookEndpoint`` / ``WebhookDelivery``: HMAC-SHA256 outbound event subscriptions.
    - ``AuditLog``: Immutable audit trail for security and compliance.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from typing import Any, ClassVar

from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

VALID_API_KEY_SCOPES: frozenset[str] = frozenset(
    {"tasks:read", "tasks:write", "tasks:export", "ai:write"}
)

VALID_WEBHOOK_EVENTS: frozenset[str] = frozenset(
    {
        "task.created",
        "task.updated",
        "task.completed",
        "task.deleted",
        "task.consensus_reached",
        "task.translated",
        "task.uncertainty_escalated",
        "webhook.ping",
        "ai.budget_threshold_reached",
        "ai.budget_exceeded",
        "scim.user_provisioned",
        "scim.user_deprovisioned",
        "annotator.calibrated",
        "audit.checkpoint_anchored",
    }
)


class CustomUserManager(BaseUserManager["CustomUser"]):
    """Custom manager for CustomUser where email is the unique identifier."""

    def create_user(
        self,
        email: str,
        password: str | None = None,
        **extra_fields: Any,
    ) -> "CustomUser":
        """Create and save a User with the given email and password."""
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        extra_fields.setdefault("is_active", True)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(
        self,
        email: str,
        password: str | None = None,
        **extra_fields: Any,
    ) -> "CustomUser":
        """Create and save a SuperUser with the given email and password."""
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(email, password, **extra_fields)


class CustomUser(AbstractBaseUser, PermissionsMixin):  # type: ignore[django-manager-missing]
    """Custom User model indexed by UUID and authenticated via email."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True, max_length=254)
    first_name = models.CharField(max_length=150, blank=True)
    last_name = models.CharField(max_length=150, blank=True)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(auto_now_add=True)
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)

    objects = CustomUserManager()

    USERNAME_FIELD: ClassVar[str] = "email"
    REQUIRED_FIELDS: ClassVar[list[str]] = []

    class Meta:
        db_table = "core_user"
        verbose_name = "user"
        verbose_name_plural = "users"
        ordering = ["-date_joined"]
        indexes = [
            models.Index(fields=["email"]),
            models.Index(fields=["is_active", "is_staff"]),
        ]

    def __str__(self) -> str:
        return self.email

    def get_full_name(self) -> str:
        full = f"{self.first_name} {self.last_name}".strip()
        return full or self.email

    def get_short_name(self) -> str:
        return self.first_name or self.email.split("@")[0]


class Organization(models.Model):  # type: ignore[django-manager-missing]
    """Tenant container with plan-based resource limits."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    slug = models.SlugField(unique=True)
    plan = models.CharField(
        max_length=20,
        choices=[
            ("free", "Free"),
            ("starter", "Starter"),
            ("professional", "Professional"),
            ("enterprise", "Enterprise"),
        ],
        default="free",
    )
    max_users = models.PositiveIntegerField(default=5)
    max_tasks = models.PositiveIntegerField(default=100)
    max_ai_requests = models.PositiveIntegerField(default=50)
    monthly_ai_token_budget = models.PositiveBigIntegerField(default=0)
    monthly_ai_cost_budget_microusd = models.PositiveBigIntegerField(default=0)
    ai_budget_alert_threshold_pct = models.PositiveSmallIntegerField(default=80)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["slug", "is_active"]),
            models.Index(fields=["plan", "is_active"]),
        ]

    def __str__(self) -> str:
        return self.name


class OrganizationMember(models.Model):
    """RBAC membership linking a user to an organization."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="members",
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="organization_memberships",
    )
    role = models.CharField(
        max_length=20,
        choices=[
            ("viewer", "Viewer"),
            ("contributor", "Contributor"),
            ("admin", "Admin"),
            ("owner", "Owner"),
        ],
        default="viewer",
    )
    is_billing_contact = models.BooleanField(default=False)
    scim_external_id = models.CharField(max_length=255, blank=True, default="")
    provisioned_by_scim = models.BooleanField(default=False)
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ["organization", "user"]
        indexes = [
            models.Index(fields=["organization", "role"]),
            models.Index(fields=["user", "role"]),
        ]

    def clean(self) -> None:
        """Enforce organization max_users plan seat quota on new memberships."""
        super().clean()
        if self._state.adding and self.organization_id:
            existing_count = OrganizationMember.objects.filter(
                organization_id=self.organization_id
            ).count()
            if existing_count >= self.organization.max_users:
                raise ValidationError("Organization user seat limit exceeded.")

    def save(self, *args: Any, **kwargs: Any) -> None:
        if self._state.adding and self.organization_id:
            self.clean()
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        return f"{self.user} @ {self.organization} ({self.role})"


class OrganizationAPIKey(models.Model):
    """Scoped M2M API key stored strictly as a SHA-256 hex digest."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="api_keys",
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="created_api_keys",
    )
    name = models.CharField(max_length=100)
    prefix = models.CharField(max_length=24, db_index=True)
    hashed_key = models.CharField(max_length=64, unique=True)
    role = models.CharField(
        max_length=20,
        choices=[
            ("viewer", "Viewer"),
            ("contributor", "Contributor"),
            ("admin", "Admin"),
        ],
        default="contributor",
    )
    scopes = models.JSONField(default=list, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["organization", "revoked_at"]),
            models.Index(fields=["prefix"]),
        ]

    @staticmethod
    def hash_raw_key(raw_key: str) -> str:
        """Compute deterministic SHA-256 hex digest for an API key."""
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    @classmethod
    def create_with_raw_key(
        cls,
        *,
        organization: Organization,
        created_by: Any,
        name: str,
        role: str = "contributor",
        scopes: list[str] | None = None,
        expires_at: Any = None,
    ) -> tuple["OrganizationAPIKey", str]:
        """Generate a one-time plaintext key and persist only its prefix and SHA-256 digest."""
        key_id_part = secrets.token_hex(4)
        secret_part = secrets.token_urlsafe(32)
        prefix = f"mlk_live_{key_id_part}"
        raw_key = f"{prefix}_{secret_part}"
        instance = cls.objects.create(
            organization=organization,
            created_by=created_by,
            name=name,
            prefix=prefix,
            hashed_key=cls.hash_raw_key(raw_key),
            role=role,
            scopes=list(scopes) if scopes is not None else sorted(VALID_API_KEY_SCOPES),
            expires_at=expires_at,
        )
        return instance, raw_key

    @property
    def is_usable(self) -> bool:
        """Return True when the key is neither revoked nor expired."""
        if self.revoked_at is not None:
            return False
        if self.expires_at is not None and self.expires_at <= timezone.now():
            return False
        return True

    def __str__(self) -> str:
        return f"{self.name} ({self.prefix}***)"


class WebhookEndpoint(models.Model):
    """Tenant-scoped outbound webhook endpoint signed with HMAC-SHA256."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="webhooks",
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_webhooks",
    )
    url = models.URLField(max_length=500)
    description = models.CharField(max_length=255, blank=True)
    secret = models.CharField(max_length=128)
    events = models.JSONField(default=list)
    is_active = models.BooleanField(default=True)
    failure_count = models.PositiveIntegerField(default=0)
    last_triggered_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["organization", "is_active"]),
        ]

    def __str__(self) -> str:
        return f"Webhook({self.organization_id} -> {self.url})"


class WebhookDelivery(models.Model):
    """Audit record of an outbound webhook HTTP delivery attempt."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    endpoint = models.ForeignKey(
        WebhookEndpoint,
        on_delete=models.CASCADE,
        related_name="deliveries",
    )
    event_type = models.CharField(max_length=50)
    payload = models.JSONField(default=dict)
    response_status = models.PositiveSmallIntegerField(null=True, blank=True)
    success = models.BooleanField(default=False)
    error_message = models.CharField(max_length=500, blank=True)
    delivered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-delivered_at"]
        indexes = [
            models.Index(fields=["endpoint", "-delivered_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.event_type} -> {self.response_status or 'ERR'}"


class AuditLog(models.Model):
    """Immutable audit trail for security and compliance."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="audit_logs",
        null=True,
        blank=True,
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    action = models.CharField(
        max_length=50,
        choices=[
            ("created", "Created"),
            ("updated", "Updated"),
            ("deleted", "Deleted"),
            ("restored", "Restored"),
            ("login", "Login"),
            ("logout", "Logout"),
            ("permission_changed", "Permission Changed"),
            ("ai_request", "AI Request"),
            ("cache_cleared", "Cache Cleared"),
            ("api_key_created", "API Key Created"),
            ("api_key_revoked", "API Key Revoked"),
            ("webhook_created", "Webhook Created"),
            ("webhook_deleted", "Webhook Deleted"),
            ("webhook_recovered", "Webhook Recovered"),
            ("webhook_replayed", "Webhook Replayed"),
            ("outbox_replayed", "Outbox Replayed"),
            ("sso_updated", "SSO Configuration Updated"),
            ("sso_login", "OIDC SSO Login"),
            ("scim_token_rotated", "SCIM Bearer Token Rotated"),
            ("scim_user_provisioned", "SCIM User Provisioned"),
            ("scim_user_updated", "SCIM User Updated"),
            ("scim_user_deprovisioned", "SCIM User Deprovisioned"),
            ("finops_budget_updated", "FinOps AI Budget Updated"),
            ("task_claimed", "Task Claimed"),
            ("task_annotated", "Task Annotated"),
            ("task_adjudicated", "Task Adjudicated"),
            ("task_uncertainty_triaged", "Task Uncertainty Triaged"),
            ("gold_task_evaluated", "Gold Calibration Task Evaluated"),
            ("audit_checkpoint_anchored", "Audit Chain Checkpoint Anchored"),
            ("exported", "Dataset Exported"),
        ],
    )
    resource_type = models.CharField(max_length=50)
    resource_id = models.CharField(max_length=255, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    chain_seq = models.PositiveBigIntegerField(default=0)
    prev_hash = models.CharField(max_length=64, default="0" * 64)
    entry_hash = models.CharField(max_length=64, default="", db_index=True)
    created_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        indexes = [
            models.Index(fields=["organization", "action", "created_at"]),
            models.Index(fields=["user", "created_at"]),
            models.Index(fields=["organization", "chain_seq"], name="core_auditlog_org_seq_idx"),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "chain_seq"],
                condition=models.Q(organization__isnull=False, chain_seq__gt=0),
                name="core_auditlog_uniq_org_seq",
            )
        ]
        ordering = ["-created_at"]

    def save(self, *args: Any, **kwargs: Any) -> None:
        if not self._state.adding:
            raise ValidationError("AuditLog entries are cryptographically sealed and immutable.")
        from apps.core.audit_chain import seal_and_insert_audit_log

        seal_and_insert_audit_log(self, super().save, *args, **kwargs)

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        raise ValidationError("AuditLog entries are cryptographically sealed and immutable.")

    def __str__(self) -> str:
        return f"{self.action} {self.resource_type} by {self.user} at {self.created_at}"


class AuditChainCheckpoint(models.Model):
    """Externally notarized & S3 Object-Lock WORM checkpoint over a tenant AuditLog chain."""

    ANCHOR_STATUS_CHOICES = [
        ("hmac_sealed", "HMAC Sealed"),
        ("s3_worm_locked", "S3 Object Lock WORM"),
        ("anchor_error", "External Anchor Error"),
    ]

    SIGNATURE_ALGORITHM_CHOICES = [
        ("HMAC-SHA256", "HMAC-SHA256"),
        ("Ed25519", "Ed25519"),
        ("KMS-ECDSA-SHA256", "AWS KMS ECDSA-SHA256"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="audit_checkpoints",
    )
    checkpoint_seq = models.PositiveBigIntegerField()
    covered_up_to_seq = models.PositiveBigIntegerField()
    verified_entries = models.PositiveBigIntegerField()
    head_hash = models.CharField(max_length=64)
    manifest_digest = models.CharField(max_length=64)
    prev_checkpoint_hash = models.CharField(max_length=64, default="0" * 64)
    checkpoint_hash = models.CharField(max_length=64, db_index=True)
    signature = models.CharField(max_length=64)
    signature_algorithm = models.CharField(
        max_length=32,
        choices=SIGNATURE_ALGORITHM_CHOICES,
        default="HMAC-SHA256",
    )
    public_key_fingerprint = models.CharField(max_length=64, blank=True, default="")
    asymmetric_signature = models.CharField(max_length=512, blank=True, default="")
    anchor_status = models.CharField(
        max_length=32,
        choices=ANCHOR_STATUS_CHOICES,
        default="hmac_sealed",
    )
    worm_uri = models.CharField(max_length=512, blank=True, default="")
    worm_etag = models.CharField(max_length=128, blank=True, default="")
    worm_version_id = models.CharField(max_length=128, blank=True, default="")
    retention_until = models.DateTimeField()
    anchor_error = models.CharField(max_length=500, blank=True, default="")
    created_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        ordering = ["-checkpoint_seq"]
        indexes = [
            models.Index(
                fields=["organization", "-checkpoint_seq"],
                name="core_auditckpt_org_seq_idx",
            )
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "checkpoint_seq"],
                name="core_auditckpt_uniq_org_seq",
            )
        ]

    def save(self, *args: Any, **kwargs: Any) -> None:
        if not self._state.adding:
            raise ValidationError(
                "AuditChainCheckpoint entries are cryptographically sealed and immutable."
            )
        super().save(*args, **kwargs)

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        raise ValidationError(
            "AuditChainCheckpoint entries are cryptographically sealed and immutable."
        )

    def __str__(self) -> str:
        return (
            f"AuditChainCheckpoint(org={self.organization_id}, seq={self.checkpoint_seq}, "
            f"status={self.anchor_status})"
        )


class OutboxEvent(models.Model):
    """Transactional Outbox record guaranteeing at-least-once webhook and pub/sub delivery."""

    TOPIC_CHOICES = [
        ("webhook", "Webhook"),
        ("pubsub", "Pub/Sub & WebSocket"),
    ]

    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("processing", "Processing"),
        ("dispatched", "Dispatched"),
        ("failed", "Failed"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="outbox_events",
        null=True,
        blank=True,
    )
    topic = models.CharField(
        max_length=20,
        choices=TOPIC_CHOICES,
        default="webhook",
    )
    event_type = models.CharField(max_length=64)
    payload = models.JSONField(default=dict)
    traceparent = models.CharField(max_length=128, blank=True, default="")
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default="pending",
    )
    attempts = models.PositiveSmallIntegerField(default=0)
    next_attempt_at = models.DateTimeField(default=timezone.now)
    dispatched_at = models.DateTimeField(null=True, blank=True)
    last_error = models.CharField(max_length=500, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]
        indexes = [
            models.Index(
                fields=["status", "next_attempt_at", "created_at"],
                name="core_outbox_pending_idx",
            ),
            models.Index(
                fields=["organization", "-created_at"],
                name="core_outbox_org_created_idx",
            ),
        ]

    def __str__(self) -> str:
        return f"OutboxEvent({self.topic}:{self.event_type} [{self.status}])"


class OrganizationSSOConfig(models.Model):
    """Per-organization OIDC token-exchange and RFC 7644 SCIM 2.0 configuration."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.OneToOneField(
        Organization,
        on_delete=models.CASCADE,
        related_name="sso_config",
    )
    enabled = models.BooleanField(default=False)
    oidc_issuer = models.CharField(max_length=500, blank=True, default="")
    oidc_client_id = models.CharField(max_length=255, blank=True, default="")
    jwks_json = models.JSONField(default=dict, blank=True)
    public_key_pem = models.TextField(blank=True, default="")
    allowed_domains = models.JSONField(default=list, blank=True)
    role_claim = models.CharField(max_length=100, default="groups")
    role_mapping = models.JSONField(default=dict, blank=True)
    default_role = models.CharField(
        max_length=20,
        choices=[
            ("viewer", "Viewer"),
            ("contributor", "Contributor"),
            ("admin", "Admin"),
        ],
        default="viewer",
    )
    jit_provisioning = models.BooleanField(default=True)
    scim_enabled = models.BooleanField(default=False)
    scim_token_prefix = models.CharField(max_length=24, blank=True, default="")
    scim_token_hash = models.CharField(max_length=64, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    @staticmethod
    def hash_scim_token(raw_token: str) -> str:
        """Compute deterministic SHA-256 hex digest for a SCIM bearer token."""
        return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    def rotate_scim_token(self) -> str:
        """Generate a new SCIM 2.0 bearer token and persist only its prefix and SHA-256 digest."""
        token_id = secrets.token_hex(4)
        secret_part = secrets.token_urlsafe(32)
        prefix = f"scim_live_{token_id}"
        raw_token = f"{prefix}_{secret_part}"
        self.scim_token_prefix = prefix
        self.scim_token_hash = self.hash_scim_token(raw_token)
        self.scim_enabled = True
        self.save(
            update_fields=[
                "scim_token_prefix",
                "scim_token_hash",
                "scim_enabled",
                "updated_at",
            ]
        )
        return raw_token

    def __str__(self) -> str:
        return f"SSOConfig({self.organization_id} enabled={self.enabled} scim={self.scim_enabled})"


class AIUsageLog(models.Model):
    """Immutable FinOps ledger entry for per-tenant monthly OpenAI token and cost governance."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="ai_usage_logs",
        null=True,
        blank=True,
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="ai_usage_logs",
    )
    operation = models.CharField(max_length=50, default="chat.completions")
    model_name = models.CharField(max_length=64, default="gpt-4o-mini")
    prompt_tokens = models.PositiveIntegerField(default=0)
    completion_tokens = models.PositiveIntegerField(default=0)
    total_tokens = models.PositiveIntegerField(default=0)
    cost_nanousd = models.PositiveBigIntegerField(default=0)
    billing_period = models.CharField(max_length=7, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(
                fields=["organization", "billing_period", "-created_at"],
                name="core_aiusage_org_period_idx",
            ),
        ]

    def __str__(self) -> str:
        return f"AIUsageLog({self.organization_id} {self.billing_period} {self.total_tokens} tok)"
