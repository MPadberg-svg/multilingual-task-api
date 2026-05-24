"""Test settings for multilingual-task-api."""

from __future__ import annotations

from .base import *  # noqa: F401,F403

DATABASES = {  # type: ignore[misc]  # noqa: F405
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}
