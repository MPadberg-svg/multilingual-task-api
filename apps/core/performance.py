"""Performance utilities for query profiling and optimized database access.

Provides:
    - ``QueryProfiler``: Context manager to detect N+1 queries and slow
      execution times.
    - ``optimized_task_queryset``: Pre-fetched, select-related queryset
      for active tasks.
    - ``batch_update_tasks``: Bulk status update across many tasks.
    - ``bulk_create_translations``: Efficient bulk creation of
      django-parler translations.
"""

import logging
import time
from contextlib import contextmanager

from django.conf import settings
from django.db import connection

logger = logging.getLogger(__name__)


@contextmanager
def QueryProfiler(threshold_ms: float = 100.0, max_queries: int = 20):
    """Profile a code block for query count and execution duration.

    ``connection.queries`` is only populated when ``settings.DEBUG`` is
    truthy, so the N+1 check is skipped otherwise. Duration is always
    measured.

    Args:
        threshold_ms: Duration (ms) above which a warning is logged.
        max_queries: Query count above which an N+1 warning is logged.

    Yields:
        None.

    Example:
        >>> with QueryProfiler(threshold_ms=50.0, max_queries=5):
        ...     Task.objects.all()
    """
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


def optimized_task_queryset():
    """Return an optimized queryset for active tasks.

    Uses ``prefetch_related('translations')`` and ``select_related('user')``
    with ``.only()`` to limit column selection.

    Returns:
        QuerySet of active Task instances.
    """
    from apps.tasks.models import Task

    return (
        Task.objects.prefetch_related("translations")
        .select_related("user")
        .filter(is_active=True)
        .only(
            "id",
            "status",
            "is_active",
            "created_at",
            "updated_at",
            "user__id",
            "user__email",
        )
    )


def batch_update_tasks(task_ids: list, status: str) -> int:
    """Bulk-update task status and timestamp.

    Args:
        task_ids: List of task UUIDs to update.
        status: New status value.

    Returns:
        Number of rows updated.
    """
    from django.utils import timezone

    from apps.tasks.models import Task

    return Task.objects.filter(id__in=task_ids).update(
        status=status,
        updated_at=timezone.now(),
    )


def bulk_create_translations(tasks_data: list) -> list:
    """Bulk-create django-parler translations efficiently.

    Args:
        tasks_data: List of dicts with keys ``task_id``, ``lang``,
            ``title``, ``description``.

    Returns:
        List of created TaskTranslation instances.
    """
    from apps.tasks.models import Task

    TaskTranslation = Task._parler_meta.root_model
    return TaskTranslation.objects.bulk_create(
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
