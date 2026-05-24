"""Development settings for multilingual-task-api.

Optimized for local development with verbose logging, browsable API,
short-lived DB connections, and cache exception tolerance.
"""

from __future__ import annotations

from . import base as base_settings

DATABASES = base_settings.DATABASES
REST_FRAMEWORK = base_settings.REST_FRAMEWORK
LOGGING = base_settings.LOGGING
CACHES = base_settings.CACHES

for _name in dir(base_settings):
    if _name.isupper():
        globals()[_name] = getattr(base_settings, _name)
del _name, base_settings

# =============================================================================
# Debug Mode
# =============================================================================
DEBUG = True

ALLOWED_HOSTS = ["*"]

# =============================================================================
# Database — Disable persistent connections in development
# =============================================================================
DATABASES["default"]["CONN_MAX_AGE"] = 0  # type: ignore[index]

# =============================================================================
# DRF — Enable browsable API in development
# =============================================================================
REST_FRAMEWORK["DEFAULT_RENDERER_CLASSES"] = [
    "rest_framework.renderers.JSONRenderer",
    "rest_framework.renderers.BrowsableAPIRenderer",
]

# =============================================================================
# Email
# =============================================================================
EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"

# =============================================================================
# Celery — Use real broker in development (not eager)
# =============================================================================
CELERY_TASK_ALWAYS_EAGER = False

# =============================================================================
# Logging — Verbose application logs
# =============================================================================
LOGGING["loggers"]["apps"]["level"] = "DEBUG"

# =============================================================================
# Cache — Gracefully degrade if Redis is unavailable during development
# =============================================================================
CACHES["default"]["OPTIONS"]["IGNORE_EXCEPTIONS"] = True  # type: ignore[index]
