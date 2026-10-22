"""App configuration for the core platform application."""

from __future__ import annotations

from django.apps import AppConfig


class CoreConfig(AppConfig):
    """Configuration class for the core Django application."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.core"
    verbose_name = "Core Platform"

    def ready(self) -> None:
        """Trigger Celery task discovery when Django apps are fully loaded."""
        from config.celery import discover_tasks

        discover_tasks()
