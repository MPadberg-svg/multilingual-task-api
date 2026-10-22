"""Performance utilities for query profiling and optimized database access."""

from __future__ import annotations

import logging
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from django.conf import settings
from django.db import connection
from django.db.models import QuerySet

logger = logging.getLogger(__name__)


@contextmanager
def QueryProfiler(threshold_ms: float = 100.0, max_queries: int = 20) -> Iterator[None]:
    """Profile a code block for query count and execution duration."""
    start = time.perf_counter()
    query_count = len(connection.queries) if settings.DEBUG else 0

    yield

    duration_ms = (time.perf_counter() - start) * 1000

    if settings.DEBUG:
        queries_executed = len(connection.queries) - query_count
        if queries_executed > max_queries:
            logger.warning(
                "N+1 detected: %s queries executed (threshold: %s)",
                queries_executed,
                max_queries,
            )
    if duration_ms > threshold_ms:
        logger.warning(
            "Slow query detected: %.2fms (threshold: %.2fms)",
            duration_ms,
            threshold_ms,
        )


def optimized_task_queryset() -> QuerySet[Any]:
    """Return an optimized queryset for active tasks."""
    from apps.tasks.models import Task

    return (
        Task.objects.prefetch_related("translations")
        .select_related("user", "organization")
        .filter(is_active=True)
        .only(
            "id",
            "status",
            "is_active",
            "created_at",
            "updated_at",
            "organization_id",
            "user__id",
            "user__email",
        )
    )


def batch_update_tasks(task_ids: list[str], status: str) -> int:
    """Bulk-update task status and timestamp."""
    from django.utils import timezone

    from apps.tasks.models import Task

    return int(
        Task.objects.filter(id__in=task_ids).update(
            status=status,
            updated_at=timezone.now(),
        )
    )


def bulk_create_translations(tasks_data: list[dict[str, str]]) -> list[Any]:
    """Bulk-create django-parler translations efficiently."""
    from apps.tasks.models import Task

    TaskTranslation = Task._parler_meta.root_model
    return list(
        TaskTranslation.objects.bulk_create(
            [
                TaskTranslation(
                    master_id=d["task_id"],
                    language_code=d["lang"],
                    title=d["title"],
                    description=d["description"],
                )
                for d in tasks_data
            ]
        )
    )
