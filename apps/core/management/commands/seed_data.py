"""Management command to create demo users and multilingual tasks.

Usage:
    python manage.py seed_data --users 3 --tasks-per-user 5
"""

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from faker import Faker

from apps.tasks.models import Task

User = get_user_model()

faker_en = Faker("en_US")
faker_es = Faker("es_ES")
faker_fr = Faker("fr_FR")


class Command(BaseCommand):
    """Seed the database with demo users and multilingual tasks."""

    help = "Create demo users and multilingual tasks"

    def add_arguments(self, parser):
        """Add CLI arguments for user and task counts."""
        parser.add_argument(
            "--users",
            type=int,
            default=3,
            help="Number of demo users to create",
        )
        parser.add_argument(
            "--tasks-per-user",
            type=int,
            default=5,
            help="Number of tasks per user",
        )

    def handle(self, *args, **options):
        """Create users and seed multilingual tasks via django-parler.

        Args:
            *args: Unused positional arguments.
            **options: Parsed CLI options (users, tasks_per_user).
        """
        for u in range(options["users"]):
            user = User.objects.create_user(
                username=f"demo{u}",
                email=f"demo{u}@example.com",
                password="demo123",
            )
            self.stdout.write(f"Created user: {user.username}")

            for t in range(options["tasks_per_user"]):
                task = Task.objects.create(user=user, status="pending")

                task.set_current_language("en")
                task.title = faker_en.sentence(nb_words=4)
                task.description = faker_en.paragraph()
                task.save()

                task.set_current_language("es")
                task.title = faker_es.sentence(nb_words=4)
                task.description = faker_es.paragraph()
                task.save()

                task.set_current_language("fr")
                task.title = faker_fr.sentence(nb_words=4)
                task.description = faker_fr.paragraph()
                task.save()

        self.stdout.write(
            self.style.SUCCESS(
                f'Created {options["users"]} users with '
                f'{options["tasks_per_user"]} tasks each'
            )
        )