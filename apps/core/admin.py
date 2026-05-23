"""Django admin configuration for core infrastructure models.

Registers:
    - ``CustomUser``: Managed via customized UserAdmin using email.
    - ``Organization``: With automated slug-prepopulation.
    - ``OrganizationMember``: RBAC relation tracking.
    - ``AuditLog``: Configured as a fully read-only immutable table.
"""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.html import format_html

from apps.core.models import AuditLog, CustomUser, Organization, OrganizationMember


@admin.register(CustomUser)
class CustomUserAdmin(BaseUserAdmin):
    """Custom admin view for managing email-authenticated CustomUser instances."""

    model = CustomUser
    list_display = (
        "email",
        "first_name",
        "last_name",
        "is_staff",
        "is_active",
        "date_joined",
    )
    list_filter = ("is_staff", "is_active", "date_joined")
    search_fields = ("email", "first_name", "last_name")
    ordering = ("-date_joined",)
    readonly_fields = ("id", "date_joined", "last_login", "last_login_ip")

    fieldsets = (
        (None, {"fields": ("id", "email", "password")}),
        ("Personal Info", {"fields": ("first_name", "last_name")}),
        (
            "Permissions",
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "groups",
                    "user_permissions",
                ),
                "classes": ("collapse",),
            },
        ),
        (
            "Important Dates",
            {
                "fields": ("last_login", "date_joined", "last_login_ip"),
                "classes": ("collapse",),
            },
        ),
    )

    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": (
                    "email",
                    "first_name",
                    "last_name",
                    "password1",
                    "password2",
                    "is_staff",
                    "is_active",
                ),
            },
        ),
    )


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    """Admin configuration for Managing multi-tenant Organization nodes."""

    list_display = ("name", "slug", "plan", "is_active", "member_count")
    list_filter = ("plan", "is_active")
    search_fields = ("name", "slug")
    prepopulated_fields = {"slug": ("name",)}
    readonly_fields = ("id",)

    def member_count(self, obj):
        count = obj.members.count()
        return format_html("<b>{}</b> members", count)

    member_count.short_description = "Members"


@admin.register(OrganizationMember)
class OrganizationMemberAdmin(admin.ModelAdmin):
    """Admin representation for RBAC assignments matching users to tenants."""

    list_display = ("user", "organization", "role", "role_badge")
    list_filter = ("role", "organization")
    search_fields = ("user__email", "organization__name")
    autocomplete_fields = ("user", "organization")

    ROLE_COLORS = {
        "owner": "#dc2626",
        "admin": "#d97706",
        "contributor": "#2563eb",
        "viewer": "#6b7280",
    }

    def role_badge(self, obj):
        color = self.ROLE_COLORS.get(obj.role, "#6b7280")
        return format_html(
            '<span style="background:{};color:white;padding:2px 8px;'
            'border-radius:12px;font-size:11px;font-weight:600">{}</span>',
            color,
            obj.role.upper(),
        )

    role_badge.short_description = "Role"


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    """Admin layout for security audit tracking.

    Enforced as read-only to safeguard data immutability.
    """

    list_display = ("action", "resource_type", "user_email", "ip_address", "created_at")
    list_filter = ("action", "resource_type", "created_at")
    search_fields = ("user__email", "resource_type", "ip_address")
    readonly_fields = (
        "id",
        "action",
        "resource_type",
        "user",
        "ip_address",
        "user_agent",
        "metadata",
        "created_at",
    )
    ordering = ("-created_at",)
    date_hierarchy = "created_at"

    def user_email(self, obj):
        return obj.user.email if obj.user else "—"

    user_email.short_description = "User"

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
