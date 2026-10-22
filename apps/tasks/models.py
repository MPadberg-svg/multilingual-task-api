"""Task models with multi-tenancy, soft-delete, and django-parler translations."""

from __future__ import annotations

import uuid
from typing import Any

from django.conf import settings
from django.db import models

from parler.models import TranslatableModel, TranslatedFields


class Task(TranslatableModel):  # type: ignore[misc]
    """A multilingual task entity scoped to a user and optional organization."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
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

    def __str__(self) -> str:
        title = self.safe_translation_getter("title", any_language=True)
        return str(title) if title else str(self.id)

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        """Soft-delete: set ``is_active=False`` instead of DB deletion."""
        self.is_active = False
        self.save(update_fields=["is_active", "updated_at"])
        return 1, {self._meta.label: 1}
