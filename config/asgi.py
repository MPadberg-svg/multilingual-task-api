"""ASGI application entry point.

Configures Django ASGI with Channels routing for HTTP and WebSocket.
"""

import os

from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from django.core.asgi import get_asgi_application
from django.urls import path

from apps.core.consumers import TaskUpdateConsumer

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.development")

application = ProtocolTypeRouter(
    {
        "http": get_asgi_application(),
        "websocket": AuthMiddlewareStack(
            URLRouter(
                [
                    path("ws/tasks/<str:org_id>/", TaskUpdateConsumer.as_asgi()),
                    path("ws/tasks/", TaskUpdateConsumer.as_asgi()),
                ]
            )
        ),
    }
)