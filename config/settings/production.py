"""Production settings for multilingual-task-api.

Security-hardened configuration with HTTPS enforcement, HSTS preloading,
JSON-only API responses, strict cache failure policy, and structured logging.
"""

from __future__ import annotations

from django.core.exceptions import ImproperlyConfigured

from decouple import Csv, config

from .base import *  # noqa: F401,F403

if SECRET_KEY == "django-insecure-test-key":  # noqa: F405
    raise ImproperlyConfigured(
        "SECRET_KEY must be set via environment variable in production."
    )

# =============================================================================
# Debug Mode
# =============================================================================
DEBUG: bool = False

# =============================================================================
# Hosts — Strict allowlist from environment
# =============================================================================
ALLOWED_HOSTS: list[str] = config("ALLOWED_HOSTS", cast=Csv())  # noqa: F405

# =============================================================================
# Security Headers — HTTPS & HSTS
# =============================================================================
SECURE_SSL_REDIRECT: bool = True
SECURE_PROXY_SSL_HEADER: tuple[str, str] = ("HTTP_X_FORWARDED_PROTO", "https")
USE_X_FORWARDED_HOST: bool = True
SECURE_HSTS_SECONDS: int = 31_536_000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS: bool = True
SECURE_HSTS_PRELOAD: bool = True
SESSION_COOKIE_SECURE: bool = True
CSRF_COOKIE_SECURE: bool = True
SECURE_CONTENT_TYPE_NOSNIFF: bool = True
SECURE_BROWSER_XSS_FILTER: bool = True
X_FRAME_OPTIONS: str = "DENY"
SECURE_REDIRECT_EXEMPT: list[str] = [
    r"^api/v1/live/$",
    r"^api/v1/health/$",
    r"^api/v1/ready/$",
]

# =============================================================================
# Database — Persistent connections with statement timeout
# =============================================================================
DATABASES["default"]["CONN_MAX_AGE"] = 600  # type: ignore[index]  # noqa: F405
DATABASES["default"]["OPTIONS"] = {  # type: ignore[index]  # noqa: F405
    "options": "-c statement_timeout=30000",  # 30 seconds
    "connect_timeout": 10,
}

# =============================================================================
# DRF — JSON-only responses in production (no browsable API)
# =============================================================================
REST_FRAMEWORK["DEFAULT_RENDERER_CLASSES"] = [  # noqa: F405
    "rest_framework.renderers.JSONRenderer",
]

# =============================================================================
# Celery — Retry broker connection on startup for resilience
# =============================================================================
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP: bool = True

# =============================================================================
# Logging — Structured JSON formatter for log aggregation
# =============================================================================
LOGGING["formatters"]["json"] = {  # noqa: F405
    "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
    "format": "%(asctime)s %(levelname)s %(name)s %(message)s",
}

# Add JSON handler alongside console for production log aggregation
LOGGING["handlers"]["json"] = {  # noqa: F405
    "class": "logging.StreamHandler",
    "formatter": "json",
}

for logger_name in ("apps", "django", "django.server"):
    LOGGING["loggers"][logger_name]["handlers"] = ["console", "json"]  # noqa: F405

# =============================================================================
# Cache — Fail fast if Redis is unavailable in production
# =============================================================================
CACHES["default"]["OPTIONS"]["IGNORE_EXCEPTIONS"] = False  # type: ignore[index]  # noqa: F405
