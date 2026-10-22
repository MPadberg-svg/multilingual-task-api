"""Django admin configuration for the Task model."""

from __future__ import annotations

from django.contrib import admin
from django.db.models import QuerySet
from django.http import HttpRequest

from parler.admin import TranslatableAdmin

from apps.tasks.models import Task, TaskAnnotation


@admin.register(Task)
class TaskAdmin(TranslatableAdmin):  # type: ignore[misc]
    """Admin interface for managing multilingual tasks."""

    list_display = (
        "display_title",
        "status",
        "is_active",
        "created_at",
        "user",
    )
    list_filter = (
        "status",
        "is_active",
        "created_at",
    )
    search_fields = (
        "translations__title",
        "translations__description",
    )
    readonly_fields = (
        "id",
        "created_at",
        "updated_at",
    )
    actions = ["restore_tasks"]

    @admin.display(description="Title")
    def display_title(self, obj: Task) -> str:
        """Safely fetch the title across translations for list display view."""
        title = obj.safe_translation_getter("title", any_language=True)
        return str(title) if title else str(obj.id)

    @admin.action(description="Restore selected soft-deleted tasks")
    def restore_tasks(self, request: HttpRequest, queryset: QuerySet[Task]) -> None:
        """Bulk restore soft-deleted tasks."""
        count = queryset.update(is_active=True)
        self.message_user(
            request,
            f"{count} task{'s' if count != 1 else ''} restored.",
        )

    def get_queryset(self, request: HttpRequest) -> QuerySet[Task]:
        """Return the queryset for the admin changelist."""
        if hasattr(Task, "all_objects"):
            return Task.all_objects.all()  # type: ignore[no-any-return]
        qs: QuerySet[Task] = super().get_queryset(request)
        return qs


@admin.register(TaskAnnotation)
class TaskAnnotationAdmin(admin.ModelAdmin):  # type: ignore[type-arg]
    """Admin view for structured RLHF task annotations."""

    list_display = (
        "task",
        "annotator",
        "preference",
        "duration_seconds",
        "created_at",
    )
    list_filter = ("preference", "created_at")
    readonly_fields = ("id", "created_at")
