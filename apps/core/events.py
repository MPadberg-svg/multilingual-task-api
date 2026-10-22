"""Redis pub/sub & Django Channels event publisher for task, AI, and audit events.

Provides:
    - ``EventPublisher``: Singleton publisher that emits JSON messages to Redis
      Pub/Sub channels (``mltask:events:{org_id}:{event_type}``), forwards
      real-time task events to Django Channels WebSocket groups, and persists
      audit trails to ``AuditLog``.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from django.utils import timezone

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django_redis import get_redis_connection

logger = logging.getLogger(__name__)


class _NullRedis:
    """Stub Redis client used when no Redis backend is available (e.g. tests)."""

    def publish(self, *args: Any, **kwargs: Any) -> int:
        return 0

    def ping(self, *args: Any, **kwargs: Any) -> bool:
        return True

    def __getattr__(self, name: str) -> Any:
        return lambda *a, **kw: None


def broadcast_task_websocket_event(
    org_id: str,
    action: str,
    task_data: dict[str, Any],
) -> None:
    """Forward a task lifecycle event to authorized Django Channels WebSocket groups.

    Dispatches ``task_deleted`` for deletion events and ``task_update`` for
    creations/updates to:
        - ``org_{org_id}`` (only when ``org_id`` is a specific tenant UUID, never ``global``)
        - ``user_{user_id}`` (owner/actor channel)
        - ``task_{task_id}`` (task-specific subscribers)
    """
    try:
        channel_layer = get_channel_layer()
        if channel_layer is None:
            return

        ws_event_type = "task_deleted" if action == "deleted" else "task_update"
        payload_data = {"action": action, **task_data}
        event_message = {
            "type": ws_event_type,
            "event_id": str(uuid.uuid4()),
            "data": payload_data,
        }

        target_groups: list[str] = []
        if org_id and org_id != "global":
            target_groups.append(f"org_{org_id}")
        user_id = task_data.get("user_id")
        if user_id:
            target_groups.append(f"user_{user_id}")
        task_id = task_data.get("id")
        if task_id:
            target_groups.append(f"task_{task_id}")

        send = async_to_sync(channel_layer.group_send)
        for group_name in dict.fromkeys(target_groups):
            send(group_name, event_message)
    except Exception:
        logger.warning("Failed to broadcast task event to Channels layer", exc_info=True)


class EventPublisher:
    """Singleton Redis pub/sub & Channels publisher for domain events."""

    _instance: "EventPublisher | None" = None
    redis: Any

    def __new__(cls) -> "EventPublisher":
        """Ensure singleton with lazy Redis connection."""
        if cls._instance is None:
            instance = super().__new__(cls)
            try:
                instance.redis = get_redis_connection("default")
            except (NotImplementedError, Exception):
                instance.redis = _NullRedis()
            cls._instance = instance
        return cls._instance

    def _get_channel(self, org_id: str, event_type: str) -> str:
        """Build a scoped Redis channel name."""
        return f"mltask:events:{org_id}:{event_type}"

    def _safe_publish(
        self,
        channel: str,
        message: str,
        *,
        raise_on_error: bool = False,
    ) -> None:
        """Publish to Redis with graceful error handling unless ``raise_on_error=True``."""
        try:
            self.redis.publish(channel, message)
        except Exception:
            if raise_on_error:
                raise
            logger.warning("Failed to publish to Redis channel %s", channel, exc_info=True)

    def publish_task_event(
        self,
        org_id: str,
        action: str,
        task_data: dict[str, Any],
        *,
        raise_on_error: bool = False,
    ) -> None:
        """Publish a task lifecycle event to Redis Pub/Sub and Django Channels."""
        message = json.dumps(
            {
                "type": "task",
                "action": action,
                "data": task_data,
                "timestamp": timezone.now().isoformat(),
            }
        )
        self._safe_publish(
            self._get_channel(org_id, "tasks"),
            message,
            raise_on_error=raise_on_error,
        )
        broadcast_task_websocket_event(org_id, action, task_data)

    def publish_ai_event(
        self,
        org_id: str,
        action: str,
        ai_data: dict[str, Any],
    ) -> None:
        """Publish an AI assist event."""
        message = json.dumps(
            {
                "type": "ai",
                "action": action,
                "data": ai_data,
                "timestamp": timezone.now().isoformat(),
            }
        )
        self._safe_publish(self._get_channel(org_id, "ai"), message)

    def publish_audit_event(
        self,
        org_id: str,
        action: str,
        audit_data: dict[str, Any],
    ) -> None:
        """Publish an audit event and persist it to the database."""
        message = json.dumps(
            {
                "type": "audit",
                "action": action,
                "data": audit_data,
                "timestamp": timezone.now().isoformat(),
            }
        )
        self._safe_publish(self._get_channel(org_id, "audit"), message)
        self._persist_audit(org_id, action, audit_data)

    def _persist_audit(self, org_id: str, action: str, audit_data: dict[str, Any]) -> None:
        """Persist an audit event to the ``AuditLog`` model."""
        from apps.core.models import AuditLog, Organization

        try:
            org = Organization.objects.get(id=org_id)
            AuditLog.objects.create(
                organization=org,
                action=action,
                resource_type=audit_data.get("resource_type", "unknown"),
                resource_id=audit_data.get("resource_id", ""),
                ip_address=audit_data.get("ip"),
                user_agent=audit_data.get("user_agent", ""),
                metadata=audit_data,
            )
        except Exception:
            logger.warning("Failed to persist audit log", exc_info=True)
