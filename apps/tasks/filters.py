"""Django-filter configuration for the Task API.

Provides a FilterSet that supports searching across all configured
language translations, status filtering, active-state filtering, and
date-range filtering on creation time.
"""

from django.conf import settings
from django.db.models import Q
from django_filters import rest_framework as filters

from apps.tasks.models import Task


class TaskFilter(filters.FilterSet):
    """FilterSet for querying Task instances.

    Supports:
        - Full-text search across all language translations
          (title and description).
        - Exact status matching.
        - Active/inactive state filtering.
        - Date range filtering on ``created_at``.

    Attributes:
        search: Case-insensitive search across translated fields.
        status: Exact match on task status.
        is_active: Boolean filter for soft-delete state.
        created_after: Minimum creation timestamp (inclusive).
        created_before: Maximum creation timestamp (inclusive).
    """

    search = filters.CharFilter(
        method="filter_search",
        help_text="Search across all language translations.",
    )
    status = filters.ChoiceFilter(
        choices=Task._meta.get_field("status").choices,
        help_text="Filter by exact task status.",
    )
    is_active = filters.BooleanFilter(
        help_text="Filter by active (non-deleted) state.",
    )
    created_after = filters.DateTimeFilter(
        field_name="created_at",
        lookup_expr="gte",
        help_text="Filter tasks created on or after this timestamp.",
    )
    created_before = filters.DateTimeFilter(
        field_name="created_at",
        lookup_expr="lte",
        help_text="Filter tasks created on or before this timestamp.",
    )

    class Meta:
        """Metadata for TaskFilter."""

        model = Task
        fields = [
            "status",
            "is_active",
            "created_after",
            "created_before",
        ]

    def filter_search(
        self,
        queryset,
        name: str,
        value: str,
    ):
        """Filter tasks by searching across all language translations.

        Builds a dynamic OR query that searches the ``title`` and
        ``description`` fields in every language configured in
        ``settings.LANGUAGES``. Results are deduplicated via
        ``distinct()``.

        Args:
            queryset: The base queryset to filter.
            name: The name of the filter field (unused).
            value: The search string to match.

        Returns:
            A filtered queryset containing matching tasks.
        """
        q_objects = Q()
        languages = getattr(settings, "LANGUAGES", [("en", "English")])

        for lang_code, _lang_name in languages:
            q_objects |= (
                Q(
                    translations__language_code=lang_code,
                    translations__title__icontains=value,
                )
                | Q(
                    translations__language_code=lang_code,
                    translations__description__icontains=value,
                )
            )

        return queryset.filter(q_objects).distinct()