"""Multi-tenancy and audit models for the core app.

Provides:
    - ``Organization``: Tenant container with plan-based limits.
    - ``OrganizationMember``: RBAC membership linking users to orgs.
    - ``AuditLog``: Immutable audit trail for security and compliance.
"""

import uuid

from django.contrib.auth import get_user_model
from django.db import models

User = get_user_model()


class Organization(models.Model):
    """Tenant container with plan-based resource limits.

    Attributes:
        id: UUID primary key.
        name: Human-readable name.
        slug: Unique URL-friendly identifier.
        plan: Billing tier (free, starter, professional, enterprise).
        max_users: Seat limit.
        max_tasks: Task limit.
        max_ai_requests: Monthly AI request limit.
        is_active: Soft-delete flag.
        created_at: Timestamp.
    """

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
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["slug", "is_active"]),
            models.Index(fields=["plan", "is_active"]),
        ]

    def __str__(self):
        return self.name


class OrganizationMember(models.Model):
    """RBAC membership linking a user to an organization.

    Attributes:
        id: UUID primary key.
        organization: Parent organization.
        user: Django user instance.
        role: Access level (viewer, contributor, admin, owner).
        is_billing_contact: Whether user receives invoices.
        joined_at: Timestamp.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="members",
    )
    user = models.ForeignKey(
        User,
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
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ["organization", "user"]
        indexes = [
            models.Index(fields=["organization", "role"]),
            models.Index(fields=["user", "role"]),
        ]

    def __str__(self):
        return f"{self.user} @ {self.organization} ({self.role})"


class AuditLog(models.Model):
    """Immutable audit trail for security and compliance.

    Attributes:
        id: UUID primary key.
        organization: Optional tenant scope.
        user: Actor (nullable for system actions).
        action: Categorised action type.
        resource_type: Affected model name.
        resource_id: Affected instance identifier.
        ip_address: Client IP (nullable).
        user_agent: Client user agent string.
        metadata: Arbitrary JSON context.
        created_at: Timestamp.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="audit_logs",
        null=True,
        blank=True,
    )
    user = models.ForeignKey(
        User,
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
        ],
    )
    resource_type = models.CharField(max_length=50)
    resource_id = models.CharField(max_length=255, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["organization", "action", "created_at"]),
            models.Index(fields=["user", "created_at"]),
        ]
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.action} {self.resource_type} by {self.user} at {self.created_at}"