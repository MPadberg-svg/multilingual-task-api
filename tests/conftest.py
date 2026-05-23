"""Global pytest fixtures and configuration."""

from unittest.mock import MagicMock

import pytest


@pytest.fixture(autouse=True)
def mock_event_publisher_redis(monkeypatch):
    """Ensure EventPublisher always uses a fake Redis connection everywhere."""
    from apps.core.events import EventPublisher

    fake_redis = MagicMock()
    fake_redis.publish = MagicMock(return_value=1)
    fake_redis.set = MagicMock(return_value=True)
    fake_redis.get = MagicMock(return_value=None)
    fake_redis.delete = MagicMock(return_value=0)
    fake_redis.keys = MagicMock(return_value=[])
    fake_redis.hgetall = MagicMock(return_value={})
    fake_redis.hset = MagicMock(return_value=1)
    fake_redis.lpush = MagicMock(return_value=1)
    fake_redis.lrange = MagicMock(return_value=[])
    fake_redis.expire = MagicMock(return_value=True)

    # Create a fake instance with the fake redis
    fake_instance = MagicMock()
    fake_instance.redis = fake_redis
    fake_instance.publish_task_event = MagicMock()
    fake_instance.publish_ai_event = MagicMock()
    fake_instance.publish_audit_event = MagicMock()

    # Patch the singleton _instance
    monkeypatch.setattr(EventPublisher, "_instance", fake_instance)

    # Patch __new__ to return the fake instance
    monkeypatch.setattr(EventPublisher, "__new__", lambda cls: fake_instance)

    # Also patch get_redis_connection to return fake_redis for any direct calls
    try:
        monkeypatch.setattr("django_redis.get_redis_connection", lambda name: fake_redis)
    except ImportError:
        pass

    return fake_redis


# Keep any existing fixtures from your project below this line
