"""Django-filter configuration for the Task API."""

from __future__ import annotations

from typing import Any

from django.db.models import Exists, Field, OuterRef, Q, QuerySet
from django.db.models.lookups import IContains

from django_filters import rest_framework as filters

from apps.tasks.models import Task


@Field.register_lookup
class TrigramILike(IContains):
    """Case-insensitive substring lookup compiling to native PostgreSQL ``ILIKE`` (``pg_trgm``)."""

    lookup_name = "trgm_ilike"

    def as_postgresql(
        self,
        compiler: Any,
        connection: Any,
    ) -> tuple[str, list[Any]]:
        lhs, lhs_params = self.process_lhs(compiler, connection)
        rhs, rhs_params = self.process_rhs(compiler, connection)
        return f"{lhs} ILIKE {rhs}", [*lhs_params, *rhs_params]

    def get_rhs_op(self, connection: Any, rhs: str) -> str:
        return str(connection.operators["icontains"] % rhs)


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
    domain = filters.ChoiceFilter(
        choices=Task._meta.get_field("domain").choices,
        help_text="Filter by task domain specialization.",
    )
    difficulty = filters.ChoiceFilter(
        choices=Task._meta.get_field("difficulty").choices,
        help_text="Filter by task difficulty tier.",
    )
    min_uncertainty = filters.NumberFilter(
        field_name="uncertainty_score",
        lookup_expr="gte",
        help_text="Filter tasks with active-learning uncertainty score >= threshold.",
    )
    auto_escalated = filters.BooleanFilter(
        field_name="auto_escalated",
        help_text="Filter tasks promoted via active-learning uncertainty escalation.",
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
            "domain",
            "difficulty",
            "min_uncertainty",
            "auto_escalated",
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
        """Filter tasks across translations via an ``EXISTS`` ``pg_trgm`` semi-join."""
        cleaned = (value or "").strip()
        if not cleaned:
            return queryset

        translation_model = Task._parler_meta.root_model
        matching_translations = translation_model.objects.filter(
            master_id=OuterRef("pk"),
        ).filter(Q(title__trgm_ilike=cleaned) | Q(description__trgm_ilike=cleaned))

        return queryset.filter(Exists(matching_translations))
