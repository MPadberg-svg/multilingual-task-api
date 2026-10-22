"""Management command to pre-populate Redis cache after deployment.

Warms real per-user and per-organization task list (paginated structure) and
task detail cache keys matching ``TaskViewSet`` key conventions.

Usage:
    python manage.py warm_cache --languages en es fr --limit 100
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from django.conf import settings
from django.core.cache import cache
from django.core.management.base import BaseCommand, CommandParser

from apps.tasks.models import Task
from apps.tasks.serializers import TaskSerializer
from apps.tasks.views import register_scope_cache_key


class _RequestStub:
    """Minimal request stub providing ``language`` and ``user`` for ``TaskSerializer``."""

    def __init__(self, language: str, user_id: str) -> None:
        self.language = language
        self.user = type("_UserStub", (), {"id": user_id})()


class Command(BaseCommand):
    """Warm Redis cache with serialized task data for real user/org scopes."""

    help = "Pre-populate Redis cache after deployment"

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "--languages",
            nargs="+",
            default=["en", "es", "fr"],
            help="Languages to warm",
        )
        parser.add_argument(
            "--limit",
            type=int,
            default=100,
            help="Max tasks to cache",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        languages: list[str] = [str(code).lower() for code in options["languages"]]
        limit = int(options["limit"])
        page_size = 20

        tasks = list(
            Task.objects.filter(is_active=True)
            .select_related("user", "organization")
            .prefetch_related("translations")[:limit]
        )

        by_user: dict[str, list[Task]] = defaultdict(list)
        by_org: dict[str, list[Task]] = defaultdict(list)
        for task in tasks:
            by_user[str(task.user_id)].append(task)
            if task.organization_id:
                by_org[f"org:{task.organization_id}"].append(task)

        for lang in languages:
            # Warm user-scoped list (first page) + detail caches
            for user_id, user_tasks in by_user.items():
                context = {"request": _RequestStub(lang, user_id)}
                first_page = user_tasks[:page_size]
                list_payload = {
                    "count": len(user_tasks),
                    "next": None,
                    "previous": None,
                    "results": TaskSerializer(first_page, many=True, context=context).data,
                }
                list_key = f"mltask:task_list:{user_id}:{lang}:"
                cache.set(list_key, list_payload, settings.CACHE_TTL["task_list"])
                register_scope_cache_key(user_id, list_key)

                for task in user_tasks:
                    detail_key = f"mltask:task_detail:{user_id}:{lang}:{task.id}"
                    detail_data = TaskSerializer(task, context=context).data
                    cache.set(detail_key, detail_data, settings.CACHE_TTL["task_detail"])
                    register_scope_cache_key(user_id, detail_key)

            # Warm organization-scoped list + detail caches
            for org_scope, org_tasks in by_org.items():
                context = {"request": _RequestStub(lang, org_scope)}
                first_page = org_tasks[:page_size]
                list_payload = {
                    "count": len(org_tasks),
                    "next": None,
                    "previous": None,
                    "results": TaskSerializer(first_page, many=True, context=context).data,
                }
                list_key = f"mltask:task_list:{org_scope}:{lang}:"
                cache.set(list_key, list_payload, settings.CACHE_TTL["task_list"])
                register_scope_cache_key(org_scope, list_key)

                for task in org_tasks:
                    detail_key = f"mltask:task_detail:{org_scope}:{lang}:{task.id}"
                    detail_data = TaskSerializer(task, context=context).data
                    cache.set(detail_key, detail_data, settings.CACHE_TTL["task_detail"])
                    register_scope_cache_key(org_scope, detail_key)

        self.stdout.write(
            self.style.SUCCESS(f"Warmed cache for {len(tasks)} tasks in {len(languages)} languages")
        )
