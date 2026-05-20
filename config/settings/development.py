"""Development settings for multilingual-task-api.

Optimized for local development with verbose logging, browsable API,
short-lived DB connections, and cache exception tolerance.
"""

from __future__ import annotations

from typing import Any

from .base import *  # noqa: F401,F403

# =============================================================================
# Debug Mode
# =============================================================================
DEBUG: bool = True

ALLOWED_HOSTS: list[str] = ["*"]

# =============================================================================
# Database — Disable persistent connections in development
# =============================================================================
DATABASES["default"]["CONN_MAX_AGE"] = 0  # type: ignore[index]  # noqa: F405

# =============================================================================
# DRF — Enable browsable API in development
# =============================================================================
REST_FRAMEWORK["DEFAULT_RENDERER_CLASSES"] = [  # noqa: F405
    "rest_framework.renderers.JSONRenderer",
    "rest_framework.renderers.BrowsableAPIRenderer",
]

# =============================================================================
# Email
# =============================================================================
EMAIL_BACKEND: str = "django.core.mail.backends.console.EmailBackend"

# =============================================================================
# Celery — Use real broker in development (not eager)
# =============================================================================
CELERY_TASK_ALWAYS_EAGER: bool = False

# =============================================================================
# Logging — Verbose application logs
# =============================================================================
LOGGING["loggers"]["apps"]["level"] = "DEBUG"  # noqa: F405

# =============================================================================
# Cache — Gracefully degrade if Redis is unavailable during development
# =============================================================================
CACHES["default"]["OPTIONS"]["IGNORE_EXCEPTIONS"] = True  # type: ignore[index]  # noqa: F405