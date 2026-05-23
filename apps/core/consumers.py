"""WebSocket consumers for real-time task updates.

Provides:
    - ``TaskUpdateConsumer``: Authenticated async JSON consumer that
      joins organization-scoped and user-scoped channel groups.
"""

import logging

from django.contrib.auth import get_user_model

from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncJsonWebsocketConsumer
from rest_framework_simplejwt.tokens import AccessToken

User = get_user_model()

logger = logging.getLogger(__name__)


class TaskUpdateConsumer(AsyncJsonWebsocketConsumer):
    """Real-time task update consumer with JWT auth and group subscriptions.

    Routes:
        - ``ws/tasks/<str:org_id>/`` — organization-scoped connection.
        - ``ws/tasks/`` — global (unscoped) connection.

    Groups joined on connect:
        - ``org_{organization_id}``
        - ``user_{user_id}``

    Additional groups via ``receive_json``:
        - ``task_{task_id}`` — per-task subscription.
    """

    async def connect(self):
        """Authenticate via JWT query param and join channel groups.

        Closes with code ``4001`` on missing/invalid token.
        """
        self.user = None
        self.organization_id = None

        query_string = self.scope["query_string"].decode()
        token = None
        if "token=" in query_string:
            token = query_string.split("token=")[1].split("&")[0]

        if not token:
            await self.close(code=4001)
            return

        try:
            payload = AccessToken(token)
            user_id = payload["user_id"]
            self.user = await database_sync_to_async(User.objects.get)(id=user_id)
            self.organization_id = self.scope["url_route"]["kwargs"].get("org_id", "global")

            await self.channel_layer.group_add(f"org_{self.organization_id}", self.channel_name)
            await self.channel_layer.group_add(f"user_{user_id}", self.channel_name)
            await self.accept()
            await self.send_json(
                {
                    "type": "connection_established",
                    "organization_id": self.organization_id,
                    "user_id": str(user_id),
                }
            )
        except Exception as exc:
            logger.warning("WS auth failed: %s", exc)
            await self.close(code=4001)

    async def disconnect(self, close_code):
        """Leave all joined channel groups on disconnect."""
        if self.user:
            await self.channel_layer.group_discard(f"user_{self.user.id}", self.channel_name)
        if self.organization_id:
            await self.channel_layer.group_discard(f"org_{self.organization_id}", self.channel_name)

    async def receive_json(self, content, **kwargs):
        """Handle incoming client messages.

        Supported types:
            - ``ping`` → respond with ``pong``.
            - ``subscribe_task`` → join ``task_{task_id}`` group.
        """
        msg_type = content.get("type")

        if msg_type == "ping":
            await self.send_json({"type": "pong"})
        elif msg_type == "subscribe_task":
            task_id = content.get("task_id")
            if task_id:
                await self.channel_layer.group_add(f"task_{task_id}", self.channel_name)
                await self.send_json({"type": "subscribed", "task_id": task_id})

    async def task_update(self, event):
        """Broadcast task update event to the client."""
        await self.send_json({"type": "task_update", "data": event.get("data", {})})

    async def task_deleted(self, event):
        """Broadcast task deletion event to the client."""
        await self.send_json({"type": "task_deleted", "data": event.get("data", {})})
