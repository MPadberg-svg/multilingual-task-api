"""Production settings for multilingual-task-api.

Security-hardened configuration with HTTPS enforcement, ALB proxy header
support, HSTS preloading, JSON-only API responses, strict cache failure
policy, and single-stream structured JSON logging.
"""

from __future__ import annotations

from django.core.exceptions import ImproperlyConfigured

from decouple import Csv, config

from .base import *  # noqa: F401,F403

# =============================================================================
# Secret Validation — Fail fast on weak or placeholder secrets
# =============================================================================
_INSECURE_SECRET_PLACEHOLDERS = {
    "",
    "change-me-in-production",
    "dev-insecure-secret-key-local-only-0123456789abcdef",
    "test-secret-key-not-for-production",
    "test-secret-key-not-for-production-0123456789abcdef",
}
if SECRET_KEY in _INSECURE_SECRET_PLACEHOLDERS or len(SECRET_KEY) < 32:  # noqa: F405
    raise ImproperlyConfigured(
        "Production SECRET_KEY must be a non-placeholder secret of at least 32 characters."
    )

# =============================================================================
# Debug Mode
# =============================================================================
DEBUG: bool = False

# =============================================================================
# Hosts & Trusted Origins — Strict allowlists from environment
# =============================================================================
ALLOWED_HOSTS: list[str] = config("ALLOWED_HOSTS", cast=Csv())
if not ALLOWED_HOSTS:
    raise ImproperlyConfigured("ALLOWED_HOSTS must not be empty in production.")

CSRF_TRUSTED_ORIGINS: list[str] = config("CSRF_TRUSTED_ORIGINS", default="", cast=Csv())

# =============================================================================
# Security Headers — HTTPS, ALB Proxy Termination & HSTS
# =============================================================================
SECURE_PROXY_SSL_HEADER: tuple[str, str] = ("HTTP_X_FORWARDED_PROTO", "https")
USE_X_FORWARDED_HOST: bool = config("USE_X_FORWARDED_HOST", default=True, cast=bool)
TRUSTED_PROXY_COUNT: int = config("TRUSTED_PROXY_COUNT", default=1, cast=int)

SECURE_SSL_REDIRECT: bool = config("SECURE_SSL_REDIRECT", default=True, cast=bool)
# Exempt internal orchestrator/ALB HTTP health probes on container port 8000
SECURE_REDIRECT_EXEMPT: list[str] = [
    r"^api/v1/(live|health|ready)/$",
]

SECURE_HSTS_SECONDS: int = 31_536_000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS: bool = True
SECURE_HSTS_PRELOAD: bool = True
SESSION_COOKIE_SECURE: bool = True
SESSION_COOKIE_HTTPONLY: bool = True
CSRF_COOKIE_SECURE: bool = True
SECURE_CONTENT_TYPE_NOSNIFF: bool = True
X_FRAME_OPTIONS: str = "DENY"

# =============================================================================
# Database — Persistent connections with statement timeout
# =============================================================================
for _db_alias in ("default", "replica"):
    if _db_alias in DATABASES:  # noqa: F405
        DATABASES[_db_alias]["CONN_MAX_AGE"] = 600  # type: ignore[index]  # noqa: F405
        DATABASES[_db_alias]["OPTIONS"] = {  # type: ignore[index]  # noqa: F405
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
# Logging — Single structured JSON stream handler (no duplicate emission)
# =============================================================================
LOGGING["formatters"]["json"] = {  # noqa: F405
    "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
    "format": "%(asctime)s %(levelname)s %(name)s %(message)s",
    "datefmt": "%Y-%m-%dT%H:%M:%SZ",
}
LOGGING["handlers"]["console"]["formatter"] = "json"  # noqa: F405
LOGGING["root"]["handlers"] = ["console"]  # noqa: F405
for _logger_name in ("apps", "django", "django.server", "celery"):
    LOGGING["loggers"][_logger_name]["handlers"] = ["console"]  # noqa: F405

# =============================================================================
# Cache — Fail fast if Redis is unavailable in production
# =============================================================================
CACHES["default"]["OPTIONS"]["IGNORE_EXCEPTIONS"] = False  # type: ignore[index]  # noqa: F405
