"""Celery async tasks for the tasks app.

Provides background task processing for:
    - Bulk translation generation via OpenAI
    - Cache invalidation across all language variants
    - Audit log event persistence
    - Email notifications (placeholder)
"""

from __future__ import annotations

import logging
from typing import Any

from celery import shared_task
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone

from apps.ai_assist.services import AIService
from apps.core.events import EventPublisher
from apps.core.models import AuditLog, Organization
from apps.tasks.models import Task

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def generate_task_translations(self, task_id: str, user_input: str) -> dict[str, Any]:
    """Generate EN/ES/FR translations for a task via OpenAI.

    Args:
        task_id: UUID of the Task to translate.
        user_input: Raw description or title to translate.

    Returns:
        Dict with generated translations.

    Raises:
        self.retry: On OpenAI failure, retries up to 3 times.
    """
    try:
        task = Task.objects.get(id=task_id)
    except Task.DoesNotExist:
        logger.warning("Task %s not found for translation", task_id)
        return {}

    service = AIService()
    try:
        result = service.suggest_task_translations(
            user_id=str(task.user.id),
            lang="en",
            user_input=user_input,
        )

        # Apply translations to the task
        for lang in ("en", "es", "fr"):
            if lang in result:
                task.set_current_language(lang)
                task.title = result[lang].get("title", task.title or "")
                task.description = result[lang].get(
                    "description", task.description or ""
                )
                task.save()

        logger.info("Translations generated for task %s", task_id)
        return result

    except Exception as exc:
        logger.error("Translation generation failed: %s", exc)
        raise self.retry(exc=exc)


@shared_task
def invalidate_task_cache(task_id: str, user_id: str) -> None:
    """Invalidate all language variants of a task's cache entries.

    Args:
        task_id: UUID of the affected task.
        user_id: UUID of the user whose caches to clear.
    """
    languages = [code for code, _ in settings.LANGUAGES]

    for lang in languages:
        list_key = f"mltask:task_list:{user_id}:{lang}:"
        detail_key = f"mltask:task_detail:{user_id}:{lang}:{task_id}"
        cache.delete(list_key)
        cache.delete(detail_key)

    logger.info("Cache invalidated for task %s (user %s)", task_id, user_id)


@shared_task
def persist_audit_log(
    org_id: str | None,
    action: str,
    resource_type: str,
    resource_id: str,
    user_id: str | None,
    ip_address: str | None,
    user_agent: str,
    metadata: dict[str, Any],
) -> None:
    """Persist an audit event asynchronously.

    Args:
        org_id: Organization UUID or None.
        action: Audit action type.
        resource_type: Affected model name.
        resource_id: Affected instance identifier.
        user_id: Actor user ID or None.
        ip_address: Client IP or None.
        user_agent: Client user agent string.
        metadata: Extra JSON context.
    """
    from django.contrib.auth import get_user_model

    User = get_user_model()

    organization = None
    if org_id:
        try:
            organization = Organization.objects.get(id=org_id)
        except Organization.DoesNotExist:
            pass

    user = None
    if user_id:
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            pass

    AuditLog.objects.create(
        organization=organization,
        user=user,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=ip_address,
        user_agent=user_agent,
        metadata=metadata,
    )

    logger.info("Audit log persisted: %s %s", action, resource_type)


@shared_task
def send_task_notification_email(task_id: str, event_type: str) -> None:
    """Placeholder for async email notifications.

    Args:
        task_id: UUID of the task triggering the notification.
        event_type: Type of event (created, updated, deleted).
    """
    logger.info("Notification email queued for task %s (%s)", task_id, event_type)
    # TODO: Implement email backend integration (SES, SendGrid, etc.)