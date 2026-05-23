"""Tests for EventPublisher — Redis pub/sub event publishing.

Covers:
    - Task event publishing to correct channels
    - Channel naming convention
    - Payload structure (task ID inclusion)
    - Graceful handling of Redis connection errors
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from apps.core.events import EventPublisher


class TestEventPublisher:
    """Tests for the Redis pub/sub event publisher."""

    def _get_mocked_publisher(self):
        """Create a publisher with mocked Redis for isolated testing."""
        fake_redis = MagicMock()
        fake_redis.publish = MagicMock(return_value=1)

        # Reset singleton and create fresh instance
        EventPublisher._instance = None
        publisher = EventPublisher.__new__(EventPublisher)
        publisher.redis = fake_redis
        EventPublisher._instance = publisher

        return publisher

    def test_publish_task_event(self):
        """EventPublisher must publish a task event to Redis."""
        publisher = self._get_mocked_publisher()
        task_data = {
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "title": "Test Task",
            "status": "pending",
        }

        publisher.publish_task_event(
            org_id="org-123",
            action="created",
            task_data=task_data,
        )

        assert publisher.redis.publish.called

    def test_publish_task_event_uses_correct_channel(self):
        """Channel must follow naming convention: mltask:events:{org_id}:tasks."""
        publisher = self._get_mocked_publisher()
        task_data = {"id": "task-1", "title": "Task"}

        publisher.publish_task_event(
            org_id="org-abc",
            action="updated",
            task_data=task_data,
        )

        call_args = publisher.redis.publish.call_args
        channel = call_args[0][0]
        assert channel == "mltask:events:org-abc:tasks"

    def test_publish_task_event_includes_task_id(self):
        """Published JSON payload must include the task ID in the data field."""
        publisher = self._get_mocked_publisher()
        task_id = "550e8400-e29b-41d4-a716-446655440000"
        task_data = {
            "id": task_id,
            "title": "Important Task",
            "status": "completed",
        }

        publisher.publish_task_event(
            org_id="org-xyz",
            action="deleted",
            task_data=task_data,
        )

        call_args = publisher.redis.publish.call_args
        message_json = call_args[0][1]
        message = json.loads(message_json)

        assert message["type"] == "task"
        assert message["action"] == "deleted"
        assert "timestamp" in message
        assert message["data"]["id"] == task_id
        assert message["data"]["title"] == "Important Task"

    def test_publish_handles_redis_error_gracefully(self):
        """EventPublisher must not raise even if Redis is down."""
        from apps.core.events import EventPublisher

        failing_redis = MagicMock()
        failing_redis.publish.side_effect = ConnectionError("Redis connection refused")

        EventPublisher._instance = None
        publisher = EventPublisher.__new__(EventPublisher)
        publisher.redis = failing_redis
        EventPublisher._instance = publisher

        try:
            publisher.publish_task_event(
                org_id="org-1",
                action="created",
                task_data={"id": "task-1", "title": "Task"},
            )
        except Exception as exc:
            pytest.fail(f"EventPublisher raised an unexpected exception: {exc}")

        assert failing_redis.publish.called

    def test_publish_ai_event(self):
        """EventPublisher must publish AI events to the ai channel."""
        publisher = self._get_mocked_publisher()
        ai_data = {"model": "gpt-4", "tokens_used": 150}

        publisher.publish_ai_event(
            org_id="org-456",
            action="suggestion_generated",
            ai_data=ai_data,
        )

        call_args = publisher.redis.publish.call_args
        channel = call_args[0][0]
        message = json.loads(call_args[0][1])

        assert channel == "mltask:events:org-456:ai"
        assert message["type"] == "ai"
        assert message["action"] == "suggestion_generated"
        assert message["data"]["model"] == "gpt-4"

    def test_publish_audit_event(self):
        """EventPublisher must publish audit events and attempt DB persistence."""
        publisher = self._get_mocked_publisher()
        audit_data = {
            "resource_type": "task",
            "resource_id": "task-789",
            "ip": "192.168.1.1",
            "user_agent": "Mozilla/5.0",
        }

        with patch.object(publisher, "_persist_audit") as mock_persist:
            publisher.publish_audit_event(
                org_id="org-789",
                action="task_deleted",
                audit_data=audit_data,
            )

            call_args = publisher.redis.publish.call_args
            channel = call_args[0][0]
            message = json.loads(call_args[0][1])

            assert channel == "mltask:events:org-789:audit"
            assert message["type"] == "audit"
            assert message["action"] == "task_deleted"
            mock_persist.assert_called_once_with("org-789", "task_deleted", audit_data)
