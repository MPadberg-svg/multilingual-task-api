"""Django admin configuration for the Task model.

Provides a TranslatableAdmin interface with soft-delete awareness,
allowing administrators to view and restore soft-deleted tasks.
"""

from django.contrib import admin
from parler.admin import TranslatableAdmin

from apps.tasks.models import Task


@admin.register(Task)
class TaskAdmin(TranslatableAdmin):
    """Admin interface for managing multilingual tasks.

    Features:
        - Translatable fields (title, description) via django-parler.
        - Soft-delete visibility and bulk restore action.
        - Search across all translations.
        - Filtering by status, active state, and creation date.
    """

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
    def display_title(self, obj) -> str:
        """Safely fetch the title across translations for list display view."""
        return obj.safe_translation_getter("title", any_language=True) or str(obj.id)

    def restore_tasks(self, request, queryset) -> None:
        """Bulk restore soft-deleted tasks.

        Sets ``is_active=True`` for all selected tasks and notifies
        the admin user of the number restored.

        Args:
            request: The current HTTP request.
            queryset: QuerySet of Task instances to restore.
        """
        count = queryset.update(is_active=True)
        self.message_user(
            request,
            f"{count} task{'s' if count != 1 else ''} restored.",
        )

    restore_tasks.short_description = "Restore selected soft-deleted tasks"

    def get_queryset(self, request) -> "QuerySet[Task]":
        """Return the queryset for the admin changelist.

        Includes soft-deleted tasks so administrators can view and
        restore them. Falls back to the default queryset if
        ``all_objects`` is not available on the model manager.

        Args:
            request: The current HTTP request.

        Returns:
            A QuerySet containing all tasks, including soft-deleted ones.
        """
        if hasattr(Task, "all_objects"):
            return Task.all_objects.all()
        return super().get_queryset(request)