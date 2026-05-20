"""Celery application configuration for multilingual-task-api.

Configures task routing by queue, auto-discovers tasks from INSTALLED_APPS,
and binds to Django settings via the CELERY_ namespace.
"""

from __future__ import annotations

import os
from typing import Any

from celery import Celery

# Set the default Django settings module before Celery app initialization.
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.development")

# Initialize Celery application.
app: Celery = Celery("multilingual_task_api")

# Load configuration from Django settings with CELERY_ prefix.
app.config_from_object("django.conf:settings", namespace="CELERY")

# Auto-discover tasks from all installed Django apps.
app.autodiscover_tasks(lambda: settings.INSTALLED_APPS)  # type: ignore[name-defined]  # noqa: F821

# Route tasks to dedicated queues by app domain.
app.conf.task_routes: dict[str, dict[str, str]] = {
    "apps.tasks.tasks.*": {"queue": "tasks"},
    "apps.ai_assist.services.*": {"queue": "ai"},
}