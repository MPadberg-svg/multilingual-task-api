"""Idempotent management command to seed demo users and multilingual tasks.

Works both when ``Faker`` is installed (dev/test) and in slim production
containers where ``Faker`` is not bundled, using built-in EN/ES/FR fallback
annotation samples.

Usage:
    python manage.py seed_data --users 3 --tasks-per-user 5
"""

from __future__ import annotations

from typing import Any

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandParser

from apps.tasks.models import Task

User = get_user_model()

_FALLBACK_SAMPLES: list[dict[str, tuple[str, str]]] = [
    {
        "en": (
            "Review RLHF preference rankings",
            "Verify pairwise annotator agreement and flag ambiguous rubric items.",
        ),
        "es": (
            "Revisar clasificaciones de preferencia RLHF",
            "Verifique el acuerdo entre anotadores y marque criterios ambiguos.",
        ),
        "fr": (
            "Examiner les classements de préférence RLHF",
            "Vérifiez l'accord entre annotateurs et signalez les critères ambigus.",
        ),
    },
    {
        "en": (
            "Audit multilingual safety prompts",
            "Evaluate adversarial prompts across English, Spanish, and French locales.",
        ),
        "es": (
            "Auditar prompts de seguridad multilingües",
            "Evalúe prompts adversarios en inglés, español y francés.",
        ),
        "fr": (
            "Auditer les invites de sécurité multilingues",
            "Évaluez les invites contradictoires en anglais, espagnol et français.",
        ),
    },
]


def _build_generators() -> tuple[Any, Any, Any] | None:
    try:
        from faker import Faker  # type: ignore[import-not-found]

        return Faker("en_US"), Faker("es_ES"), Faker("fr_FR")
    except ImportError:
        return None


class Command(BaseCommand):
    """Seed the database with demo users and multilingual tasks idempotently."""

    help = "Create demo users and multilingual tasks (idempotent)"

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "--users",
            type=int,
            default=3,
            help="Number of demo users to ensure exist",
        )
        parser.add_argument(
            "--tasks-per-user",
            type=int,
            default=5,
            help="Target number of tasks per user",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        num_users = int(options["users"])
        tasks_per_user = int(options["tasks_per_user"])
        generators = _build_generators()

        for u in range(num_users):
            email = f"demo{u}@example.com"
            user, created = User.objects.get_or_create(email=email)
            if created:
                user.set_password("demo123")
                user.save(update_fields=["password"])
                self.stdout.write(f"Created user: {user.email}")
            else:
                self.stdout.write(f"Using existing user: {user.email}")

            existing_count = Task.objects.filter(user=user).count()
            to_create = max(0, tasks_per_user - existing_count)

            for t in range(to_create):
                task = Task.objects.create(user=user, status="pending")
                sample = _FALLBACK_SAMPLES[(u + t) % len(_FALLBACK_SAMPLES)]

                for idx, lang_code in enumerate(("en", "es", "fr")):
                    task.set_current_language(lang_code)
                    if generators is not None:
                        faker_inst = generators[idx]
                        task.title = faker_inst.sentence(nb_words=4)
                        task.description = faker_inst.paragraph()
                    else:
                        task.title, task.description = sample[lang_code]
                    task.save()

        self.stdout.write(
            self.style.SUCCESS(f"Seeded {num_users} users with up to {tasks_per_user} tasks each")
        )
