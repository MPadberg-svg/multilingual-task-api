"""Django app configuration for the tasks app."""

from __future__ import annotations

from django.apps import AppConfig


class TasksConfig(AppConfig):
    """Tasks application configuration."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.tasks"
    verbose_name = "Tasks"

    def ready(self) -> None:
        """Import signal receivers when the app is ready."""
        import apps.tasks.signals  # noqa: F401
