"""Tests for TaskUpdateConsumer WebSocket endpoint."""

import json
import pytest
from asgiref.sync import sync_to_async
from channels.testing import WebsocketCommunicator
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import AccessToken

from config.asgi import application

User = get_user_model()


@pytest.mark.asyncio
@pytest.mark.django_db(transaction=True)
class TestTaskUpdateConsumer:
    """Tests for the WebSocket task update consumer."""

    async def _make_user(self):
        return await sync_to_async(User.objects.create_user)(
            email="ws_test@example.com",
            password="testpass123",
        )

    async def test_connect_with_valid_jwt_succeeds(self):
        user = await self._make_user()
        token = str(AccessToken.for_user(user))

        communicator = WebsocketCommunicator(
            application,
            f"/ws/tasks/?token={token}"
        )
        connected, _ = await communicator.connect()
        assert connected is True, "WebSocket should accept a valid JWT token"
        await communicator.disconnect()

    async def test_connect_without_token_is_rejected(self):
        communicator = WebsocketCommunicator(
            application,
            "/ws/tasks/"
        )
        connected, code = await communicator.connect()
        assert not connected or code in (4001, 4003), (
            "WebSocket should reject unauthenticated connections"
        )

    async def test_connect_with_invalid_token_is_rejected(self):
        communicator = WebsocketCommunicator(
            application,
            "/ws/tasks/?token=invalid.jwt.token"
        )
        connected, code = await communicator.connect()
        assert not connected or code in (4001, 4003)

    async def test_disconnect_cleans_up_gracefully(self):
        user = await self._make_user()
        token = str(AccessToken.for_user(user))

        communicator = WebsocketCommunicator(
            application,
            f"/ws/tasks/?token={token}"
        )
        await communicator.connect()
        await communicator.disconnect()
        # No assertion needed — just verifying no exception is raised