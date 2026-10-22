"""WebSocket consumers for real-time task updates.

Provides:
    - ``TaskUpdateConsumer``: Authenticated async JSON consumer with strict
      tenant membership verification, task ownership verification, active-user
      enforcement, bounded per-socket group subscriptions, and clean teardown.
"""

from __future__ import annotations

import json
import logging
import uuid
from collections import deque
from typing import Any
from urllib.parse import parse_qs

from django.contrib.auth import get_user_model

from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncJsonWebsocketConsumer
from rest_framework_simplejwt.tokens import AccessToken

from apps.core.models import OrganizationMember
from apps.tasks.models import Task

User = get_user_model()

logger = logging.getLogger(__name__)

MAX_TASK_SUBSCRIPTIONS = 50


def _check_org_membership(user_id: Any, org_id: str) -> bool:
    """Verify the user belongs to an active Organization matching ``org_id``."""
    try:
        parsed = uuid.UUID(str(org_id))
    except (ValueError, TypeError):
        return False
    return OrganizationMember.objects.filter(
        organization_id=parsed,
        organization__is_active=True,
        user_id=user_id,
    ).exists()


def _check_task_access(user_id: Any, task_id: str) -> str | None:
    """Return canonical task UUID string if ``user_id`` may subscribe to ``task_id``."""
    try:
        parsed = uuid.UUID(str(task_id))
    except (ValueError, TypeError):
        return None

    try:
        task = Task.objects.only("id", "user_id", "organization_id", "is_active").get(
            id=parsed,
            is_active=True,
        )
    except Task.DoesNotExist:
        return None

    if str(task.user_id) == str(user_id):
        return str(task.id)
    if (
        task.organization_id
        and OrganizationMember.objects.filter(
            organization_id=task.organization_id,
            organization__is_active=True,
            user_id=user_id,
        ).exists()
    ):
        return str(task.id)
    return None


class TaskUpdateConsumer(AsyncJsonWebsocketConsumer):
    """Real-time task update consumer with JWT auth and tenant-verified subscriptions."""

    def _extract_token(self) -> str | None:
        """Extract JWT from ``Authorization: Bearer`` header (preferred) or ``?token=`` param."""
        raw_headers = dict(self.scope.get("headers") or [])
        auth_bytes = raw_headers.get(b"authorization", b"")
        if auth_bytes:
            auth_str = auth_bytes.decode("latin1").strip()
            if auth_str.lower().startswith("bearer "):
                candidate = auth_str[7:].strip()
                if candidate:
                    return candidate

        raw_qs = self.scope.get("query_string", b"").decode("utf-8", errors="ignore")
        parsed_qs = parse_qs(raw_qs, keep_blank_values=False)
        tokens = parsed_qs.get("token")
        if tokens and tokens[0].strip():
            return tokens[0].strip()
        return None

    async def connect(self) -> None:
        """Authenticate JWT, verify active status and tenant membership, and join groups."""
        self.user: Any = None
        self.organization_id: str | None = None
        self.joined_org_group: str | None = None
        self.subscribed_task_groups: set[str] = set()
        self._seen_event_ids: deque[str] = deque(maxlen=64)

        token = self._extract_token()
        if not token:
            await self.close(code=4001)
            return

        try:
            payload = AccessToken(token)  # type: ignore[arg-type]
            user_id = payload["user_id"]
            user = await database_sync_to_async(User.objects.get)(id=user_id, is_active=True)
            self.user = user
        except Exception as exc:
            logger.warning("WS auth failed: %s", exc)
            await self.close(code=4001)
            return

        requested_org_id = self.scope.get("url_route", {}).get("kwargs", {}).get("org_id")
        if requested_org_id:
            is_member = await database_sync_to_async(_check_org_membership)(
                self.user.id, str(requested_org_id)
            )
            if not is_member:
                logger.warning(
                    "WS forbidden org subscription attempt user=%s org=%s",
                    self.user.id,
                    requested_org_id,
                )
                await self.close(code=4003)
                return
            self.organization_id = str(uuid.UUID(str(requested_org_id)))
            self.joined_org_group = f"org_{self.organization_id}"
            await self.channel_layer.group_add(self.joined_org_group, self.channel_name)
        else:
            # Unscoped connections receive only the user's own events (no shared global group)
            self.organization_id = "global"

        await self.channel_layer.group_add(f"user_{self.user.id}", self.channel_name)
        await self.accept()
        await self.send_json(
            {
                "type": "connection_established",
                "organization_id": self.organization_id,
                "user_id": str(self.user.id),
            }
        )

    async def disconnect(self, close_code: int) -> None:
        """Leave all joined user, organization, and per-task channel groups."""
        if getattr(self, "user", None) is not None:
            await self.channel_layer.group_discard(f"user_{self.user.id}", self.channel_name)
        if getattr(self, "joined_org_group", None):
            await self.channel_layer.group_discard(self.joined_org_group, self.channel_name)
        for group_name in list(getattr(self, "subscribed_task_groups", set())):
            await self.channel_layer.group_discard(group_name, self.channel_name)
        if hasattr(self, "subscribed_task_groups"):
            self.subscribed_task_groups.clear()

    async def receive(
        self,
        text_data: str | None = None,
        bytes_data: bytes | None = None,
        **kwargs: Any,
    ) -> None:
        """Decode incoming JSON frames safely without crashing on malformed text."""
        if text_data is None:
            await self.send_json({"type": "error", "code": "invalid_payload"})
            return
        try:
            parsed = json.loads(text_data)
        except json.JSONDecodeError:
            await self.send_json({"type": "error", "code": "invalid_json"})
            return
        await self.receive_json(parsed, **kwargs)

    async def receive_json(self, content: Any, **kwargs: Any) -> None:
        """Handle incoming client control messages."""
        if not isinstance(content, dict):
            await self.send_json({"type": "error", "code": "invalid_payload"})
            return

        msg_type = content.get("type") or content.get("action")

        if msg_type == "ping":
            await self.send_json({"type": "pong"})
        elif msg_type == "subscribe_task":
            raw_task_id = content.get("task_id")
            if not raw_task_id:
                await self.send_json({"type": "error", "code": "missing_task_id"})
                return
            if len(self.subscribed_task_groups) >= MAX_TASK_SUBSCRIPTIONS:
                await self.send_json({"type": "error", "code": "subscription_limit_exceeded"})
                return

            canonical_task_id = await database_sync_to_async(_check_task_access)(
                self.user.id, str(raw_task_id)
            )
            if canonical_task_id is None:
                await self.send_json({"type": "error", "code": "forbidden_or_not_found"})
                return

            group_name = f"task_{canonical_task_id}"
            await self.channel_layer.group_add(group_name, self.channel_name)
            self.subscribed_task_groups.add(group_name)
            await self.send_json({"type": "subscribed", "task_id": canonical_task_id})
        elif msg_type == "unsubscribe_task":
            raw_task_id = content.get("task_id")
            if not raw_task_id:
                await self.send_json({"type": "error", "code": "missing_task_id"})
                return
            try:
                canonical_id = str(uuid.UUID(str(raw_task_id)))
            except (ValueError, TypeError):
                await self.send_json({"type": "error", "code": "invalid_task_id"})
                return
            group_name = f"task_{canonical_id}"
            await self.channel_layer.group_discard(group_name, self.channel_name)
            self.subscribed_task_groups.discard(group_name)
            await self.send_json({"type": "unsubscribed", "task_id": canonical_id})
        else:
            await self.send_json({"type": "error", "code": "unknown_message_type"})

    def _is_duplicate_event(self, event: dict[str, Any]) -> bool:
        """Suppress duplicate delivery when a socket belongs to overlapping groups."""
        event_id = event.get("event_id")
        if not event_id:
            return False
        seen = getattr(self, "_seen_event_ids", None)
        if seen is None:
            self._seen_event_ids = deque([str(event_id)], maxlen=64)
            return False
        if str(event_id) in seen:
            return True
        seen.append(str(event_id))
        return False

    async def task_update(self, event: dict[str, Any]) -> None:
        """Broadcast task creation/update event to the client."""
        if self._is_duplicate_event(event):
            return
        await self.send_json({"type": "task_update", "data": event.get("data", {})})

    async def task_deleted(self, event: dict[str, Any]) -> None:
        """Broadcast task deletion event to the client."""
        if self._is_duplicate_event(event):
            return
        await self.send_json({"type": "task_deleted", "data": event.get("data", {})})
