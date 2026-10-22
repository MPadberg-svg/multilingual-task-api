"""Celery application configuration with W3C distributed trace propagation.

Configures task routing by queue, auto-discovers tasks from INSTALLED_APPS,
binds to Django settings via the CELERY_ namespace, and propagates W3C
``traceparent`` context from producers into worker task spans.
"""

from __future__ import annotations

import os
from typing import Any

from celery import Celery
from celery.signals import before_task_publish, task_postrun, task_prerun

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.development")

app: Celery = Celery("multilingual_task_api")
app.config_from_object("django.conf:settings", namespace="CELERY")

app.conf.task_routes = {
    "apps.tasks.tasks.*": {"queue": "tasks"},
    "apps.ai_assist.*": {"queue": "ai"},
}

app.autodiscover_tasks()

_ACTIVE_CELERY_SPANS: dict[str, Any] = {}


@before_task_publish.connect
def _inject_traceparent_on_publish(headers: dict[str, Any] | None = None, **kwargs: Any) -> None:
    """Propagate active W3C ``traceparent`` into outbound Celery task headers."""
    if headers is None:
        return
    from apps.core.tracing import get_current_traceparent

    tp = get_current_traceparent()
    if tp and "traceparent" not in headers:
        headers["traceparent"] = tp


@task_prerun.connect
def _start_celery_worker_span(task_id: str | None = None, task: Any = None, **kwargs: Any) -> None:
    """Restore producer trace context and start a ``CONSUMER`` span for the task."""
    if not task_id or task is None:
        return
    from apps.core.tracing import start_span

    req = getattr(task, "request", None)
    parent_tp = getattr(req, "traceparent", None)
    if not parent_tp and req is not None:
        req_headers = getattr(req, "headers", None) or {}
        if isinstance(req_headers, dict):
            parent_tp = req_headers.get("traceparent")

    task_name = str(getattr(task, "name", "celery.task"))
    cm = start_span(
        f"celery.task:{task_name}",
        kind="CONSUMER",
        parent_traceparent=parent_tp,
        attributes={"messaging.system": "celery", "celery.task_id": task_id},
    )
    span = cm.__enter__()
    _ACTIVE_CELERY_SPANS[task_id] = (cm, span)


@task_postrun.connect
def _finish_celery_worker_span(
    task_id: str | None = None, state: str | None = None, **kwargs: Any
) -> None:
    """Close and export the active Celery worker span."""
    if not task_id:
        return
    entry = _ACTIVE_CELERY_SPANS.pop(task_id, None)
    if entry is None:
        return
    cm, span = entry
    if state:
        span.set_attribute("celery.state", state)
        if state == "FAILURE":
            span.set_error("Celery task failed")
    cm.__exit__(None, None, None)


def discover_tasks() -> None:
    """Discover tasks from all installed Django apps."""
    from django.conf import settings

    app.autodiscover_tasks(lambda: settings.INSTALLED_APPS)
