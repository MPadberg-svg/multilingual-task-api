"""Redis pub/sub event publisher for real-time task, AI, and audit events.

Provides:
    - ``EventPublisher``: Singleton publisher using Django-Redis connection.
      Publishes JSON messages to scoped channels and persists audit events
      to the database.

Channel naming convention:
    ``mltask:events:{org_id}:{event_type}``
"""

import json
import logging

from django.utils import timezone
from django_redis import get_redis_connection

logger = logging.getLogger(__name__)


class EventPublisher:
    """Singleton Redis pub/sub publisher for domain events.

    Automatically initialises the Redis connection on first instantiation.
    """

    _instance = None

    def __new__(cls):
        """Ensure singleton with lazy Redis connection."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.redis = get_redis_connection("default")
        return cls._instance

    def _get_channel(self, org_id: str, event_type: str) -> str:
        """Build a scoped Redis channel name.

        Args:
            org_id: Organization UUID or ``global`` for unscoped events.
            event_type: Event category (``tasks``, ``ai``, ``audit``).

        Returns:
            Channel name string.
        """
        return f"mltask:events:{org_id}:{event_type}"

    def _safe_publish(self, channel: str, message: str) -> None:
        """Publish to Redis with graceful error handling.

        Logs a warning if Redis is unavailable instead of crashing.
        """
        try:
            self.redis.publish(channel, message)
        except Exception:
            logger.warning("Failed to publish to Redis channel %s", channel, exc_info=True)

    def publish_task_event(
        self,
        org_id: str,
        action: str,
        task_data: dict,
    ) -> None:
        """Publish a task lifecycle event.

        Args:
            org_id: Organization scope.
            action: Lifecycle action (``created``, ``updated``, ``deleted``).
            task_data: Serialized task payload.
        """
        message = json.dumps(
            {
                "type": "task",
                "action": action,
                "data": task_data,
                "timestamp": timezone.now().isoformat(),
            }
        )
        self._safe_publish(self._get_channel(org_id, "tasks"), message)

    def publish_ai_event(
        self,
        org_id: str,
        action: str,
        ai_data: dict,
    ) -> None:
        """Publish an AI assist event.

        Args:
            org_id: Organization scope.
            action: AI action type.
            ai_data: Serialized AI payload.
        """
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
        audit_data: dict,
    ) -> None:
        """Publish an audit event and persist it to the database.

        Args:
            org_id: Organization scope.
            action: Audit action type.
            audit_data: Serialized audit payload.
        """
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

    def _persist_audit(self, org_id: str, action: str, audit_data: dict) -> None:
        """Persist an audit event to the ``AuditLog`` model.

        Args:
            org_id: Organization UUID.
            action: Audit action type.
            audit_data: Payload dict with optional ``resource_type``,
                ``resource_id``, ``ip``, ``user_agent``, and extra metadata.
        """
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