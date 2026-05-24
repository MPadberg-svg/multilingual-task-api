"""Test settings for multilingual-task-api."""

from __future__ import annotations

from .base import *  # noqa: F401,F403

DATABASES = {  # type: ignore[misc]  # noqa: F405
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

# Ensure test suite is fully infrastructure-isolated.
CACHES = {  # type: ignore[misc]  # noqa: F405
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "mltask-test-cache",
    }
}

SESSION_ENGINE = "django.contrib.sessions.backends.db"

CHANNEL_LAYERS = {  # type: ignore[misc]  # noqa: F405
    "default": {
        "BACKEND": "channels.layers.InMemoryChannelLayer",
    }
}

CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = True
CELERY_BROKER_URL = "memory://"
CELERY_RESULT_BACKEND = "cache+memory://"
