"""Testing settings for multilingual-task-api.

Uses SQLite (in-memory) instead of PostgreSQL and disables external services
so the full test suite can run without Docker or any running infrastructure.
"""

from __future__ import annotations

from .base import *  # noqa: F401,F403

# =============================================================================
# Core
# =============================================================================
DEBUG: bool = True
ALLOWED_HOSTS: list[str] = ["*"]

SECRET_KEY: str = "test-secret-key-not-for-production"  # noqa: S105

# =============================================================================
# Database — SQLite in-memory for speed; no PostgreSQL required
# =============================================================================
DATABASES: dict = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

# =============================================================================
# Cache — local-memory; no Redis required
# =============================================================================
CACHES: dict = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "test-cache",
    }
}

# Session: use DB (not cache) so tests don't depend on Redis
SESSION_ENGINE: str = "django.contrib.sessions.backends.db"

# =============================================================================
# Channels — in-process layer; no Redis required
# =============================================================================
CHANNEL_LAYERS: dict = {
    "default": {
        "BACKEND": "channels.layers.InMemoryChannelLayer",
    }
}

# =============================================================================
# Celery — run tasks synchronously in tests
# =============================================================================
CELERY_TASK_ALWAYS_EAGER: bool = True
CELERY_TASK_EAGER_PROPAGATES: bool = True

# =============================================================================
# OpenAI — dummy key; all OpenAI calls must be mocked in tests
# =============================================================================
OPENAI_API_KEY: str = "sk-test-dummy-key"  # noqa: S105
OPENAI_MODEL: str = "gpt-4o-mini"
OPENAI_MAX_TOKENS: int = 2000
OPENAI_TEMPERATURE: float = 0.7

# =============================================================================
# Password hashing — fast hasher to keep tests snappy
# =============================================================================
PASSWORD_HASHERS: list[str] = [
    "django.contrib.auth.hashers.MD5PasswordHasher",
]

# =============================================================================
# Email — suppress all outbound email
# =============================================================================
EMAIL_BACKEND: str = "django.core.mail.backends.locmem.EmailBackend"

# =============================================================================
# Logging — silence everything except critical errors
# =============================================================================
LOGGING["loggers"]["apps"]["level"] = "CRITICAL"  # noqa: F405
