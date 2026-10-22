"""Task and RLHF annotation models with multi-tenancy, leasing, and consensus fields."""

from __future__ import annotations

import uuid
from typing import Any

from django.conf import settings
from django.db import models

from parler.models import TranslatableModel, TranslatedFields


class Task(TranslatableModel):  # type: ignore[misc]
    """A multilingual task entity supporting atomic claiming and RLHF consensus."""

    PRIORITY_CHOICES = [
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
        ("critical", "Critical"),
    ]

    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("in_progress", "In Progress"),
        ("completed", "Completed"),
        ("archived", "Archived"),
    ]

    CONSENSUS_CHOICES = [
        ("", "Unresolved"),
        ("response_a", "Response A"),
        ("response_b", "Response B"),
        ("tie", "Tie"),
        ("needs_review", "Needs Review"),
    ]

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
        choices=STATUS_CHOICES,
        default="pending",
    )
    priority = models.CharField(
        max_length=20,
        choices=PRIORITY_CHOICES,
        default="medium",
    )
    required_annotations = models.PositiveSmallIntegerField(default=3)
    claimed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="claimed_tasks",
    )
    claimed_until = models.DateTimeField(null=True, blank=True)
    consensus_score = models.FloatField(null=True, blank=True)
    consensus_choice = models.CharField(
        max_length=20,
        choices=CONSENSUS_CHOICES,
        blank=True,
        default="",
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
            models.Index(fields=["status", "priority", "claimed_until"]),
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


class TaskAnnotation(models.Model):
    """An individual RLHF preference & rubric annotation submitted for a Task."""

    PREFERENCE_CHOICES = [
        ("response_a", "Response A"),
        ("response_b", "Response B"),
        ("tie", "Tie"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    task = models.ForeignKey(
        Task,
        on_delete=models.CASCADE,
        related_name="annotations",
    )
    annotator = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="task_annotations",
    )
    preference = models.CharField(
        max_length=20,
        choices=PREFERENCE_CHOICES,
    )
    rubric_scores = models.JSONField(default=dict, blank=True)
    rationale = models.TextField(blank=True)
    response_a = models.TextField(blank=True)
    response_b = models.TextField(blank=True)
    duration_seconds = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["task", "annotator"],
                name="tasks_annotation_uniq_task_annotator",
            )
        ]
        indexes = [
            models.Index(fields=["task", "preference"]),
            models.Index(fields=["annotator", "-created_at"]),
        ]

    def __str__(self) -> str:
        return f"Annotation({self.task_id}, {self.annotator_id}, {self.preference})"
