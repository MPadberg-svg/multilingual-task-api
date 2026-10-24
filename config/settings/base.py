"""Base Django settings for multilingual-task-api.

All environment-specific configurations inherit from this module.
Secrets and environment variables are loaded via python-decouple.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any

from decouple import Csv, config

# =============================================================================
# Project Paths
# =============================================================================
BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent

# =============================================================================
# Core Django Settings
# =============================================================================
SECRET_KEY: str = config("SECRET_KEY")
DEBUG: bool = config("DEBUG", default=False, cast=bool)
ALLOWED_HOSTS: list[str] = config("ALLOWED_HOSTS", default="", cast=Csv())

INSTALLED_APPS: list[str] = [
    # Django core
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # Third-party
    "rest_framework",
    "rest_framework_simplejwt",
    "rest_framework_simplejwt.token_blacklist",
    "parler",
    "django_filters",
    "drf_spectacular",
    "channels",
    "django_celery_beat",
    # Local apps
    "apps.core",
    "apps.tasks",
    "apps.ai_assist",
    "apps.analytics",
]

MIDDLEWARE: list[str] = [
    "django.middleware.security.SecurityMiddleware",
    "apps.core.middleware.CorrelationIdMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "apps.core.middleware.LanguageResolutionMiddleware",
    "django.middleware.locale.LocaleMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "apps.core.middleware.TenantMiddleware",
    "apps.core.rls.PostgresRLSMiddleware",
    "apps.core.middleware.TenantPermissionMiddleware",
    "apps.core.idempotency.IdempotencyKeyMiddleware",
    "apps.core.middleware.RequestLoggingMiddleware",
    "apps.analytics.middleware.RequestTimingMiddleware",
    "apps.core.middleware.ContentSecurityPolicyMiddleware",
]

ROOT_URLCONF: str = "config.urls"
WSGI_APPLICATION: str = "config.wsgi.application"
ASGI_APPLICATION: str = "config.asgi.application"

TEMPLATES: list[dict[str, Any]] = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

DEFAULT_AUTO_FIELD: str = "django.db.models.BigAutoField"

# =============================================================================
# Authentication & Password Validation
# =============================================================================
AUTH_USER_MODEL: str = "core.CustomUser"

AUTH_PASSWORD_VALIDATORS: list[dict[str, str]] = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

# =============================================================================
# Internationalization
# =============================================================================
LANGUAGE_CODE: str = "en-us"
TIME_ZONE: str = "UTC"
USE_I18N: bool = True
USE_TZ: bool = True

LANGUAGES: list[tuple[str, str]] = [
    ("en", "English"),
    ("es", "Spanish"),
    ("fr", "French"),
]

LOCALE_PATHS: list[Path] = [BASE_DIR / "locale"]

PARLER_LANGUAGES: dict[str | int, Any] = {
    1: [
        {"code": "en"},
        {"code": "es"},
        {"code": "fr"},
    ],
    "default": {
        "code": "en",
        "fallbacks": ["en"],
        "hide_untranslated": False,
    },
}

# =============================================================================
# Static & Media Files
# =============================================================================
STATIC_URL: str = "static/"
STATIC_ROOT: Path = BASE_DIR / "staticfiles"
MEDIA_URL: str = "media/"
MEDIA_ROOT: Path = BASE_DIR / "media"

# =============================================================================
# Django REST Framework
# =============================================================================
REST_FRAMEWORK: dict[str, Any] = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "apps.core.authentication.OrganizationAPIKeyAuthentication",
        "apps.core.authentication.CachedJWTAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_PAGINATION_CLASS": "apps.core.pagination.StandardResultsSetPagination",
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
        "apps.core.throttling.OrganizationPlanRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": "100/day",
        "user": "1000/day",
        "health": "600/min",
        "ai_assist": "20/hour",
        "ai_assist_burst": "5/min",
        "org_free": "60/min",
        "org_starter": "300/min",
        "org_professional": "1200/min",
        "org_enterprise": "6000/min",
    },
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_RENDERER_CLASSES": [
        "rest_framework.renderers.JSONRenderer",
    ],
}

if DEBUG:
    REST_FRAMEWORK["DEFAULT_RENDERER_CLASSES"].append(
        "rest_framework.renderers.BrowsableAPIRenderer"
    )

# =============================================================================
# SimpleJWT
# =============================================================================
_JWT_SIGNING_KEY: str = config("JWT_SIGNING_KEY", default="") or SECRET_KEY

SIMPLE_JWT: dict[str, Any] = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=15),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    "UPDATE_LAST_LOGIN": True,
    "ALGORITHM": "HS256",
    "SIGNING_KEY": _JWT_SIGNING_KEY,
    "AUTH_HEADER_TYPES": ("Bearer",),
    "USER_ID_FIELD": "id",
    "USER_ID_CLAIM": "user_id",
}

# =============================================================================
# drf-spectacular (OpenAPI 3.0)
# =============================================================================
SPECTACULAR_SETTINGS: dict[str, Any] = {
    "TITLE": "Multilingual Task API",
    "DESCRIPTION": (
        "Production-grade multi-tenant REST & WebSocket API for multilingual RLHF task "
        "orchestration, atomic annotation leasing, inter-annotator consensus, OpenAI FinOps "
        "token/spend budget governance, OIDC SSO & SCIM 2.0 enterprise provisioning, scoped "
        "M2M API keys, HMAC-signed webhooks, transactional outbox relay with dead-letter "
        "replay, PostgreSQL Row-Level Security (RLS), read-replica query routing, pg_trgm "
        "search, plan-tiered rate limiting, keyset cursor pagination, and W3C/OTLP tracing."
    ),
    "VERSION": "1.7.0",
    "SERVE_INCLUDE_SCHEMA": False,
    "ENUM_NAME_OVERRIDES": {
        "AssignableRoleEnum": [
            ("viewer", "Viewer"),
            ("contributor", "Contributor"),
            ("admin", "Admin"),
        ],
        "OrganizationRoleEnum": [
            ("viewer", "Viewer"),
            ("contributor", "Contributor"),
            ("admin", "Admin"),
            ("owner", "Owner"),
        ],
    },
}

# =============================================================================
# OpenTelemetry / W3C Distributed Tracing
# =============================================================================
OTEL_SERVICE_NAME: str = config("OTEL_SERVICE_NAME", default="multilingual-task-api")
OTEL_EXPORTER_OTLP_ENDPOINT: str = config("OTEL_EXPORTER_OTLP_ENDPOINT", default="")
OTEL_EXPORTER_OTLP_HEADERS: str = config("OTEL_EXPORTER_OTLP_HEADERS", default="")

# =============================================================================
# Database & Read-Replica Routing
# =============================================================================
DATABASES: dict[str, Any] = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": config("POSTGRES_DB", default="multilingual_task_api"),
        "USER": config("POSTGRES_USER", default="postgres"),
        "PASSWORD": config("POSTGRES_PASSWORD", default=""),
        "HOST": config("POSTGRES_HOST", default="localhost"),
        "PORT": config("POSTGRES_PORT", default="5432", cast=int),
        "CONN_MAX_AGE": 600,
        "OPTIONS": {
            "connect_timeout": 10,
        },
    }
}

POSTGRES_REPLICA_HOST: str = config("POSTGRES_REPLICA_HOST", default="").strip()
POSTGRES_REPLICA_PORT: int = config(
    "POSTGRES_REPLICA_PORT",
    default=str(DATABASES["default"]["PORT"]),
    cast=int,
)
if POSTGRES_REPLICA_HOST:
    DATABASES["replica"] = {
        **DATABASES["default"],
        "HOST": POSTGRES_REPLICA_HOST,
        "PORT": POSTGRES_REPLICA_PORT,
        "TEST": {"MIRROR": "default"},
    }

DATABASE_ROUTERS: list[str] = ["apps.core.db_router.ReplicaDatabaseRouter"]

# =============================================================================
# Multi-Tenant Monthly AI FinOps Plan Ceilings (Tokens & Micro-USD)
# =============================================================================
AI_PLAN_MONTHLY_TOKEN_BUDGETS: dict[str, int] = {
    "free": 100_000,
    "starter": 1_000_000,
    "professional": 10_000_000,
    "enterprise": 100_000_000,
}

AI_PLAN_MONTHLY_COST_MICROUSD: dict[str, int] = {
    "free": 5_000_000,  # $5.00 / month
    "starter": 50_000_000,  # $50.00 / month
    "professional": 500_000_000,  # $500.00 / month
    "enterprise": 5_000_000_000,  # $5,000.00 / month
}

# =============================================================================
# Cache (Redis)
# =============================================================================
CACHES: dict[str, Any] = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": config("REDIS_URL", default="redis://localhost:6379/0"),
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
            "COMPRESSOR": "django_redis.compressors.zlib.ZlibCompressor",
            "SERIALIZER": "django_redis.serializers.json.JSONSerializer",
            "CONNECTION_POOL_KWARGS": {
                "max_connections": 100,
            },
        },
        "KEY_PREFIX": "mltask",
    }
}

SESSION_ENGINE: str = "django.contrib.sessions.backends.cache"
SESSION_CACHE_ALIAS: str = "default"

# Cache TTLs in seconds — enforced by services, never hardcoded in views
CACHE_TTL: dict[str, int] = {
    "task_list": 300,
    "task_detail": 600,
    "translations": 1800,
    "ai_suggestions": 3600,
}

# =============================================================================
# Celery
# =============================================================================
CELERY_BROKER_URL: str = config("CELERY_BROKER_URL", default="redis://localhost:6379/1")
CELERY_RESULT_BACKEND: str = config("CELERY_RESULT_BACKEND", default="redis://localhost:6379/2")
CELERY_ACCEPT_CONTENT: list[str] = ["json"]
CELERY_TASK_SERIALIZER: str = "json"
CELERY_RESULT_SERIALIZER: str = "json"
CELERY_TASK_TIME_LIMIT: int = 300
CELERY_WORKER_PREFETCH_MULTIPLIER: int = 1
CELERY_TIMEZONE: str = TIME_ZONE
CELERY_ENABLE_UTC: bool = True
CELERY_TASK_TRACK_STARTED: bool = True
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP: bool = True

OUTBOX_RETENTION_DAYS: int = config("OUTBOX_RETENTION_DAYS", default=14, cast=int)
WEBHOOK_DELIVERY_RETENTION_DAYS: int = config(
    "WEBHOOK_DELIVERY_RETENTION_DAYS", default=30, cast=int
)
AUDIT_WORM_S3_BUCKET: str = config("AUDIT_WORM_S3_BUCKET", default="").strip()
AUDIT_WORM_S3_REGION: str = config("AUDIT_WORM_S3_REGION", default="us-east-1").strip()
AUDIT_WORM_S3_ENDPOINT_HOST: str = config("AUDIT_WORM_S3_ENDPOINT_HOST", default="").strip()
AUDIT_WORM_RETENTION_DAYS: int = config("AUDIT_WORM_RETENTION_DAYS", default=365, cast=int)
AUDIT_ANCHOR_SIGNING_KEY: str = config("AUDIT_ANCHOR_SIGNING_KEY", default="").strip()

CELERY_BEAT_SCHEDULE: dict[str, dict[str, Any]] = {
    "drain-transactional-outbox": {
        "task": "apps.tasks.tasks.drain_outbox_events",
        "schedule": 15.0,
        "kwargs": {"batch_size": 50},
    },
    "prune-outbox-and-webhook-history": {
        "task": "apps.tasks.tasks.prune_telemetry_and_outbox_history",
        "schedule": 86400.0,
        "kwargs": {"chunk_size": 500},
    },
    "anchor-audit-chain-checkpoints": {
        "task": "apps.tasks.tasks.anchor_audit_chain_checkpoints",
        "schedule": 3600.0,
        "kwargs": {"batch_size": 100},
    },
}

# =============================================================================
# Channels (WebSocket)
# =============================================================================
CHANNEL_LAYERS: dict[str, Any] = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [config("REDIS_URL", default="redis://localhost:6379/0")],
        },
    },
}

# =============================================================================
# Logging & Observability
# =============================================================================
LOG_LEVEL: str = config("LOG_LEVEL", default="INFO")
_USE_JSON_LOGS: bool = config("JSON_LOGS", default=False, cast=bool)
METRICS_AUTH_TOKEN: str = config("METRICS_AUTH_TOKEN", default="")

LOGGING: dict[str, Any] = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
            "format": "%(asctime)s %(name)s %(levelname)s %(message)s",
            "datefmt": "%Y-%m-%dT%H:%M:%SZ",
        },
        "verbose": {
            "format": "[{asctime}] [{levelname}] [{name}] {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "json" if _USE_JSON_LOGS else "verbose",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": LOG_LEVEL,
    },
    "loggers": {
        "apps": {
            "handlers": ["console"],
            "level": LOG_LEVEL,
            "propagate": False,
        },
        "django": {
            "handlers": ["console"],
            "level": "WARNING",
            "propagate": False,
        },
        "django.server": {
            "handlers": ["console"],
            "level": "WARNING",
            "propagate": False,
        },
        "celery": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
    },
}

# =============================================================================
# OpenAI Configuration
# =============================================================================
OPENAI_API_KEY: str = config("OPENAI_API_KEY", default="")
OPENAI_MODEL: str = config("OPENAI_MODEL", default="gpt-4o-mini")
OPENAI_MAX_TOKENS: int = config("OPENAI_MAX_TOKENS", default=2000, cast=int)
OPENAI_TEMPERATURE: float = config("OPENAI_TEMPERATURE", default=0.7, cast=float)

# =============================================================================
# Security & Proxy Defaults (hardened in production.py)
# =============================================================================
SECURE_CONTENT_TYPE_NOSNIFF: bool = True
X_FRAME_OPTIONS: str = "DENY"
SESSION_COOKIE_HTTPONLY: bool = True
SESSION_COOKIE_SAMESITE: str = "Lax"
CSRF_COOKIE_SAMESITE: str = "Lax"
TRUSTED_PROXY_COUNT: int = config("TRUSTED_PROXY_COUNT", default=0, cast=int)

CSRF_TRUSTED_ORIGINS: list[str] = config(
    "CSRF_TRUSTED_ORIGINS",
    default="http://localhost:8000,http://127.0.0.1:8000",
    cast=Csv(),
)
