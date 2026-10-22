"""Idempotent superuser creation — safe for CI/CD pipelines and Docker entrypoints.

Usage:
    python manage.py create_superuser_if_missing \
        --email admin@example.com \
        --password adminpass123
"""

from __future__ import annotations

from typing import Any

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandParser

User = get_user_model()


class Command(BaseCommand):
    help = "Create a superuser if none exists (idempotent — safe to re-run)"

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "--email",
            required=True,
            help="Superuser email address",
        )
        parser.add_argument(
            "--password",
            required=True,
            help="Superuser password",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        email = str(options["email"])
        password = str(options["password"])

        if User.objects.filter(is_superuser=True).exists():
            self.stdout.write(self.style.WARNING("Superuser already exists. Skipping."))
            return

        User.objects.create_superuser(email=email, password=password)
        self.stdout.write(self.style.SUCCESS(f"Superuser created: {email}"))
