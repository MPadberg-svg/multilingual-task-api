"""Django project configuration for multilingual-task-api.

Exposes the Celery application at the project root so that
`from config import celery_app` works as expected.
"""

from __future__ import annotations

from .celery import app as celery_app

__all__: tuple[str, ...] = ("celery_app",)
