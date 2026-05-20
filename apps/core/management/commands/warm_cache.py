"""Management command to pre-populate Redis cache after deployment.

Usage:
    python manage.py warm_cache --languages en es fr --limit 100
"""

from django.conf import settings
from django.core.cache import cache
from django.core.management.base import BaseCommand

from apps.tasks.models import Task
from apps.tasks.serializers import TaskSerializer


class Command(BaseCommand):
    """Warm Redis cache with serialized task data for specified languages."""

    help = "Pre-populate Redis cache after deployment"

    def add_arguments(self, parser):
        """Add CLI arguments for languages and task limit."""
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

    def handle(self, *args, **options):
        """Warm cache for active tasks across requested languages.

        Args:
            *args: Unused positional arguments.
            **options: Parsed CLI options (languages, limit).
        """
        languages = options["languages"]
        limit = options["limit"]

        tasks = Task.objects.filter(is_active=True)[:limit]

        # Build a minimal request-like object for serializer context
        for lang in languages:
            request_stub = type(
                "obj",
                (object,),
                {
                    "language": lang,
                    "user": type("obj", (object,), {"id": "system"}),
                },
            )
            context = {"request": request_stub}

            list_key = f"mltask:task_list:system:{lang}:"
            list_serializer = TaskSerializer(tasks, many=True, context=context)
            cache.set(list_key, list_serializer.data, settings.CACHE_TTL["task_list"])

            for task in tasks:
                detail_key = f"mltask:task_detail:system:{lang}:{task.id}"
                detail_serializer = TaskSerializer(task, context=context)
                cache.set(
                    detail_key,
                    detail_serializer.data,
                    settings.CACHE_TTL["task_detail"],
                )

        self.stdout.write(
            self.style.SUCCESS(
                f"Warmed cache for {len(tasks)} tasks in {len(languages)} languages"
            )
        )