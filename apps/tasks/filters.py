"""Django-filter configuration for the Task API."""

from __future__ import annotations

from django.conf import settings
from django.db.models import Q, QuerySet

from django_filters import rest_framework as filters

from apps.tasks.models import Task


class TaskFilter(filters.FilterSet):
    """FilterSet for querying Task instances across all configured languages."""

    search = filters.CharFilter(
        method="filter_search",
        help_text="Search across all language translations.",
    )
    status = filters.ChoiceFilter(
        choices=Task._meta.get_field("status").choices,
        help_text="Filter by exact task status.",
    )
    priority = filters.ChoiceFilter(
        choices=Task._meta.get_field("priority").choices,
        help_text="Filter by task priority.",
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
        model = Task
        fields = [
            "status",
            "priority",
            "is_active",
            "created_after",
            "created_before",
        ]

    def filter_search(
        self,
        queryset: QuerySet[Task],
        name: str,
        value: str,
    ) -> QuerySet[Task]:
        """Filter tasks by searching across all language translations with deduplication."""
        cleaned = (value or "").strip()
        if not cleaned:
            return queryset

        q_objects = Q()
        languages = getattr(settings, "LANGUAGES", [("en", "English")])

        for lang_code, _lang_name in languages:
            q_objects |= Q(
                translations__language_code=lang_code,
                translations__title__icontains=cleaned,
            ) | Q(
                translations__language_code=lang_code,
                translations__description__icontains=cleaned,
            )

        return queryset.filter(q_objects).distinct()
