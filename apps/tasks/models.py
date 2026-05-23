"""Task models with multi-tenancy, soft-delete, and django-parler translations.

Provides:
    - ``Task``: Core task entity with UUID, soft-delete, status, and
      organization scoping.
"""

import uuid

from django.contrib.auth import get_user_model
from django.db import models

from parler.models import TranslatableModel, TranslatedFields

User = get_user_model()


class Task(TranslatableModel):
    """A multilingual task entity scoped to a user and optional organization.

    Attributes:
        id: UUID primary key.
        user: Creator/owner.
        organization: Optional tenant scope.
        status: Workflow state.
        is_active: Soft-delete flag.
        created_at: Timestamp.
        updated_at: Auto-updated timestamp.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="tasks",
    )
    organization = models.ForeignKey(
        "core.Organization",
        on_delete=models.CASCADE,
        related_name="tasks",
        null=True,
        blank=True,
    )
    status = models.CharField(
        max_length=20,
        choices=[
            ("pending", "Pending"),
            ("in_progress", "In Progress"),
            ("completed", "Completed"),
            ("archived", "Archived"),
        ],
        default="pending",
    )
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    translations = TranslatedFields(
        title=models.CharField(max_length=255),
        description=models.TextField(blank=True),
    )

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "is_active", "status"]),
            models.Index(fields=["organization", "is_active", "status"]),
            models.Index(fields=["-created_at"]),
        ]

    def __str__(self):
        return self.safe_translation_getter("title", any_language=True) or str(self.id)

    def delete(self, *args, **kwargs):
        """Soft-delete: set ``is_active=False`` instead of DB deletion."""
        self.is_active = False
        self.save(update_fields=["is_active", "updated_at"])
