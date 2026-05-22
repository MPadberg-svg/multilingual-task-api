"""Tests for performance utilities — query profiling and optimized database access.

Covers:
    - QueryProfiler context manager (N+1 and slow query detection)
    - optimized_task_queryset returns correct queryset configuration
    - batch_update_tasks bulk update
    - bulk_create_translations efficient creation
"""

import logging
import time
from unittest.mock import MagicMock, patch

import pytest
from django.db import connection

from apps.core.performance import (
    QueryProfiler,
    batch_update_tasks,
    bulk_create_translations,
    optimized_task_queryset,
)


class TestQueryProfiler:
    """Tests for the QueryProfiler context manager."""

    @pytest.mark.django_db
    def test_profiler_logs_n1_warning(self):
        """Profiler must log warning when query count exceeds threshold."""
        with patch("apps.core.performance.logger.warning") as mock_warning:
            with patch("apps.core.performance.settings.DEBUG", True):
                connection.queries_log.clear()

                with QueryProfiler(threshold_ms=5000.0, max_queries=1):
                    from django.contrib.auth import get_user_model
                    User = get_user_model()
                    list(User.objects.all())
                    list(User.objects.all())

            mock_warning.assert_called()
            n1_calls = [call for call in mock_warning.call_args_list 
                       if "N+1 detected" in str(call)]
            assert n1_calls, f"Expected 'N+1 detected' in calls, got: {mock_warning.call_args_list}"

    def test_profiler_logs_slow_query_warning(self):
        """Profiler must log warning when execution exceeds threshold."""
        with patch("apps.core.performance.logger.warning") as mock_warning:
            with patch("apps.core.performance.settings.DEBUG", True):
                connection.queries_log.clear()

                with QueryProfiler(threshold_ms=0.001, max_queries=1000):
                    time.sleep(0.01)

            mock_warning.assert_called()
            slow_calls = [call for call in mock_warning.call_args_list 
                         if "Slow query detected" in str(call)]
            assert slow_calls, f"Expected 'Slow query detected' in calls, got: {mock_warning.call_args_list}"

    def test_profiler_yields_control(self):
        """Profiler context manager must execute the wrapped code."""
        executed = False

        with QueryProfiler():
            executed = True

        assert executed is True


class TestOptimizedTaskQueryset:
    """Tests for the optimized task queryset helper."""

    @pytest.mark.django_db
    def test_optimized_task_queryset_prefetch_and_select(self):
        """Queryset must use prefetch_related and select_related."""
        qs = optimized_task_queryset()

        # Check prefetch_related via the queryset's internal attribute
        # This works on all Django queryset subclasses including TranslatableQuerySet
        prefetch_lookups = getattr(qs, '_prefetch_related_lookups', ())
        assert prefetch_lookups, "Expected prefetch_related to be set"
        lookup_names = [str(lookup) for lookup in prefetch_lookups]
        assert any("translations" in name for name in lookup_names)

        # Check select_related via the query's select_related dict
        select_related = qs.query.select_related
        assert select_related, "Expected select_related to be set"
        assert "user" in select_related

    @pytest.mark.django_db
    def test_optimized_task_queryset_filters_active_only(self):
        """Queryset must only include active tasks."""
        qs = optimized_task_queryset()
        query_str = str(qs.query)

        assert "is_active" in query_str
        assert qs.query.where  # has WHERE clause


class TestBatchUpdateTasks:
    """Tests for bulk task status updates."""

    @pytest.mark.django_db
    def test_batch_update_tasks_returns_count(self):
        """Must return the number of rows updated."""
        from apps.tasks.models import Task
        from django.contrib.auth import get_user_model
        User = get_user_model()

        # Patch the signal handler to avoid real Redis connection
        with patch("apps.tasks.signals.EventPublisher") as mock_publisher_cls:
            mock_publisher = MagicMock()
            mock_publisher_cls.return_value = mock_publisher

            user = User.objects.create_user(email="batch@example.com", password="pass")
            task1 = Task.objects.create(user=user, status="pending")
            task2 = Task.objects.create(user=user, status="pending")

        updated = batch_update_tasks(
            task_ids=[str(task1.id), str(task2.id)],
            status="completed",
        )

        assert updated == 2
        task1.refresh_from_db()
        task2.refresh_from_db()
        assert task1.status == "completed"
        assert task2.status == "completed"

    @pytest.mark.django_db
    def test_batch_update_tasks_updates_timestamp(self):
        """Must update the updated_at timestamp."""
        from apps.tasks.models import Task
        from django.contrib.auth import get_user_model
        User = get_user_model()

        with patch("apps.tasks.signals.EventPublisher") as mock_publisher_cls:
            mock_publisher = MagicMock()
            mock_publisher_cls.return_value = mock_publisher

            user = User.objects.create_user(email="batch2@example.com", password="pass")
            task = Task.objects.create(user=user, status="pending")
            old_updated = task.updated_at

            time.sleep(0.01)

        batch_update_tasks(task_ids=[str(task.id)], status="in_progress")

        task.refresh_from_db()
        assert task.updated_at > old_updated


class TestBulkCreateTranslations:
    """Tests for efficient bulk translation creation."""

    @pytest.mark.django_db
    def test_bulk_create_translations_returns_list(self):
        """Must return a list of created translations."""
        from apps.tasks.models import Task
        from django.contrib.auth import get_user_model
        User = get_user_model()

        with patch("apps.tasks.signals.EventPublisher") as mock_publisher_cls:
            mock_publisher = MagicMock()
            mock_publisher_cls.return_value = mock_publisher

            user = User.objects.create_user(email="bulk@example.com", password="pass")
            task = Task.objects.create(user=user, status="pending")

        task_data = [
            {
                "task_id": str(task.id),
                "lang": "es",
                "title": "Tarea en Español",
                "description": "Descripción",
            },
            {
                "task_id": str(task.id),
                "lang": "fr",
                "title": "Tâche en Français",
                "description": "Description",
            },
        ]

        result = bulk_create_translations(tasks_data=task_data)

        assert isinstance(result, list)
        assert len(result) == 2

    @pytest.mark.django_db
    def test_bulk_create_translations_sets_correct_fields(self):
        """Created translations must have correct language and content."""
        from apps.tasks.models import Task
        from django.contrib.auth import get_user_model
        User = get_user_model()

        with patch("apps.tasks.signals.EventPublisher") as mock_publisher_cls:
            mock_publisher = MagicMock()
            mock_publisher_cls.return_value = mock_publisher

            user = User.objects.create_user(email="bulk2@example.com", password="pass")
            task = Task.objects.create(user=user, status="pending")

        task_data = [
            {
                "task_id": str(task.id),
                "lang": "de",
                "title": "Aufgabe",
                "description": "Beschreibung",
            }
        ]

        result = bulk_create_translations(tasks_data=task_data)
        translation = result[0]

        assert translation.language_code == "de"
        assert translation.title == "Aufgabe"
        assert translation.description == "Beschreibung"
        assert str(translation.master_id) == str(task.id)