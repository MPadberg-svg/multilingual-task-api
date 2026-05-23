"""WSGI application entry point.

Provides a standard WSGI callable for Gunicorn sync workers.
For async/WebSocket support, use ``config.asgi:application``.
"""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.production")

application = get_wsgi_application()
