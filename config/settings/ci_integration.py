"""CI / Docker integration settings backed by live PostgreSQL 16 and Redis 7.

Exercises real ``django.db.backends.postgresql`` (including ``SELECT ... FOR
UPDATE SKIP LOCKED``), ``django_redis.cache.RedisCache`` (with ``ZlibCompressor``
and ``JSONSerializer``), and ``channels_redis.core.RedisChannelLayer``.
"""

from __future__ import annotations

import os

os.environ.setdefault("SECRET_KEY", "ci-integration-secret-key-not-for-prod-0123456789abcdef")

from .base import *  # noqa: E402,F401,F403

DEBUG: bool = True
ALLOWED_HOSTS: list[str] = ["*"]

SECRET_KEY: str = "ci-integration-secret-key-not-for-prod-0123456789abcdef"  # noqa: S105
SIMPLE_JWT["SIGNING_KEY"] = config("JWT_SIGNING_KEY", default="") or SECRET_KEY  # noqa: F405

# Close connections immediately after each request/thread so pytest-django
# transaction=True teardowns and test-DB drops never hit open-socket locks.
DATABASES["default"]["CONN_MAX_AGE"] = 0  # type: ignore[index]  # noqa: F405
DATABASES["replica"] = {  # noqa: F405
    **DATABASES["default"],  # noqa: F405
    "CONN_MAX_AGE": 0,
    "TEST": {"MIRROR": "default"},
}

# Fail loudly if Redis breaks during integration tests
CACHES["default"]["OPTIONS"]["IGNORE_EXCEPTIONS"] = False  # type: ignore[index]  # noqa: F405

CELERY_TASK_ALWAYS_EAGER: bool = True
CELERY_TASK_EAGER_PROPAGATES: bool = True

OPENAI_API_KEY: str = "sk-test-dummy-key"  # noqa: S105
OPENAI_MODEL: str = "gpt-4o-mini"
OPENAI_MAX_TOKENS: int = 2000
OPENAI_TEMPERATURE: float = 0.7

PASSWORD_HASHERS: list[str] = [
    "django.contrib.auth.hashers.MD5PasswordHasher",
]

EMAIL_BACKEND: str = "django.core.mail.backends.locmem.EmailBackend"
LOGGING["loggers"]["apps"]["level"] = "CRITICAL"  # noqa: F405
