"""Celery async tasks for the tasks app.

Provides background task processing for:
    - Bulk translation generation via OpenAI
    - Cache invalidation across all language variants
    - Audit log event persistence
    - Email notifications
"""

from __future__ import annotations

import logging
from typing import Any

from django.conf import settings
from django.core.mail import send_mail

from celery import Task as CeleryTask
from celery import shared_task

from apps.ai_assist.services import AIService
from apps.core.models import AuditLog, Organization
from apps.tasks.models import Task
from apps.tasks.views import invalidate_task_caches_for_scopes

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def generate_task_translations(
    self: CeleryTask,
    task_id: str,
    user_input: str,
) -> dict[str, Any]:
    """Generate EN/ES/FR translations for a task via OpenAI.

    Safely accesses existing per-language fields via ``safe_translation_getter``
    so missing translation rows never raise ``TranslationDoesNotExist``.
    """
    try:
        task = Task.objects.select_related("user", "organization").get(id=task_id)
    except Task.DoesNotExist:
        logger.warning("Task %s not found for translation", task_id)
        return {}

    service = AIService()
    try:
        result = service.suggest_task_translations(
            user_id=str(task.user_id),
            lang="en",
            user_input=user_input,
        )

        for lang in ("en", "es", "fr"):
            if lang in result and isinstance(result[lang], dict):
                existing_title = (
                    task.safe_translation_getter("title", language_code=lang, any_language=False)
                    or ""
                )
                existing_desc = (
                    task.safe_translation_getter(
                        "description", language_code=lang, any_language=False
                    )
                    or ""
                )
                task.set_current_language(lang)
                task.title = result[lang].get("title") or existing_title
                task.description = result[lang].get("description", existing_desc)
                task.save()

        scopes = [str(task.user_id)]
        if task.organization_id:
            scopes.append(f"org:{task.organization_id}")
        invalidate_task_caches_for_scopes(scopes, task_id=str(task.id))

        logger.info("Translations generated for task %s", task_id)
        return result

    except Exception as exc:
        logger.error("Translation generation failed: %s", exc)
        raise self.retry(exc=exc)


@shared_task
def invalidate_task_cache(task_id: str, user_id: str, org_id: str | None = None) -> None:
    """Invalidate all language and query variants of a task's cache entries."""
    scopes = [str(user_id)]
    if org_id:
        scopes.append(f"org:{org_id}")
    invalidate_task_caches_for_scopes(scopes, task_id=str(task_id))
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
    """Persist an audit event asynchronously."""
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
def send_task_notification_email(task_id: str, event_type: str) -> bool:
    """Dispatch task lifecycle notification email via Django's configured email backend."""
    try:
        task = Task.objects.select_related("user").get(id=task_id)
    except Task.DoesNotExist:
        logger.warning("Skipping notification email; task %s not found", task_id)
        return False

    if not task.user.email:
        return False

    title = task.safe_translation_getter("title", any_language=True) or str(task.id)
    from_email = getattr(settings, "DEFAULT_FROM_EMAIL", "noreply@example.com")
    send_mail(
        subject=f"[Multilingual Task API] Task {event_type}: {title}",
        message=f"Your task '{title}' ({task.id}) was {event_type} (status: {task.status}).",
        from_email=from_email,
        recipient_list=[task.user.email],
        fail_silently=True,
    )
    logger.info("Notification email sent for task %s (%s)", task_id, event_type)
    return True
