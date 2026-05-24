"""Production settings for multilingual-task-api.

Security-hardened configuration with HTTPS enforcement, HSTS preloading,
JSON-only API responses, strict cache failure policy, and structured logging.
"""

from __future__ import annotations

from django.core.exceptions import ImproperlyConfigured

from decouple import Csv, config

from . import base as base_settings

SECRET_KEY = base_settings.SECRET_KEY
DATABASES = base_settings.DATABASES
REST_FRAMEWORK = base_settings.REST_FRAMEWORK
LOGGING = base_settings.LOGGING
CACHES = base_settings.CACHES

for _name in dir(base_settings):
    if _name.isupper():
        globals()[_name] = getattr(base_settings, _name)
del _name, base_settings

if SECRET_KEY == "django-insecure-test-key":
    raise ImproperlyConfigured("SECRET_KEY must be set via environment variable in production.")

# =============================================================================
# Debug Mode
# =============================================================================
DEBUG = False

# =============================================================================
# Hosts — Strict allowlist from environment
# =============================================================================
ALLOWED_HOSTS = config("ALLOWED_HOSTS", cast=Csv())

# =============================================================================
# Security Headers — HTTPS & HSTS
# =============================================================================
SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
USE_X_FORWARDED_HOST = True
SECURE_HSTS_SECONDS = 31_536_000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = "DENY"
SECURE_REDIRECT_EXEMPT = [
    r"^api/v1/live/$",
    r"^api/v1/health/$",
    r"^api/v1/ready/$",
]

# =============================================================================
# Database — Persistent connections with statement timeout
# =============================================================================
DATABASES["default"]["CONN_MAX_AGE"] = 600  # type: ignore[index]
DATABASES["default"]["OPTIONS"] = {  # type: ignore[index]
    "options": "-c statement_timeout=30000",  # 30 seconds
    "connect_timeout": 10,
}

# =============================================================================
# DRF — JSON-only responses in production (no browsable API)
# =============================================================================
REST_FRAMEWORK["DEFAULT_RENDERER_CLASSES"] = [
    "rest_framework.renderers.JSONRenderer",
]

# =============================================================================
# Celery — Retry broker connection on startup for resilience
# =============================================================================
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True

# =============================================================================
# Logging — Structured JSON formatter for log aggregation
# =============================================================================
LOGGING["formatters"]["json"] = {
    "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
    "format": "%(asctime)s %(levelname)s %(name)s %(message)s",
}

# Add JSON handler alongside console for production log aggregation
LOGGING["handlers"]["json"] = {
    "class": "logging.StreamHandler",
    "formatter": "json",
}

for logger_name in ("apps", "django", "django.server"):
    LOGGING["loggers"][logger_name]["handlers"] = ["console", "json"]

# =============================================================================
# Cache — Fail fast if Redis is unavailable in production
# =============================================================================
CACHES["default"]["OPTIONS"]["IGNORE_EXCEPTIONS"] = False  # type: ignore[index]
