"""ASGI application entry point.

Configures Django ASGI with Channels routing for HTTP and WebSocket.
"""

import os
from django.core.asgi import get_asgi_application

# 1. Set the Django settings module
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.development")

# 2. Initialize Django (Loads the App Registry)
# This MUST happen before importing anything that relies on Django models!
django_asgi_app = get_asgi_application()

# 3. Import Channels and local apps ONLY AFTER Django is initialized
from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from django.urls import path
from apps.core.consumers import TaskUpdateConsumer

# 4. Define the routing application
application = ProtocolTypeRouter(
    {
        "http": django_asgi_app,
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