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
from django.db import transaction

from celery import Task as CeleryTask
from celery import shared_task

from apps.ai_assist.services import AIService
from apps.core.events import broadcast_task_websocket_event
from apps.core.finops import AIBudgetExceededError
from apps.core.models import AuditLog, Organization, WebhookEndpoint
from apps.core.outbox import (
    drain_outbox_batch,
    enqueue_outbox_event,
    prune_outbox_and_webhook_history,
)
from apps.core.rls import rls_bypass
from apps.core.webhooks import deliver_webhook_sync
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
    with rls_bypass():
        try:
            task = Task.objects.select_related("user", "organization").get(id=task_id)
        except Task.DoesNotExist:
            logger.warning("Task %s not found for translation", task_id)
            return {}

        service = AIService()
        try:
            org_id_str = str(task.organization_id) if task.organization_id else None
            call_kwargs = {"organization_id": org_id_str} if org_id_str else {}
            result = service.suggest_task_translations(
                user_id=str(task.user_id),
                lang="en",
                user_input=user_input,
                **call_kwargs,
            )

            event_payload = {
                "id": str(task.id),
                "languages": [k for k in ("en", "es", "fr") if k in result],
                "user_id": str(task.user_id),
            }

            with transaction.atomic():
                for lang in ("en", "es", "fr"):
                    if lang in result and isinstance(result[lang], dict):
                        existing_title = (
                            task.safe_translation_getter(
                                "title", language_code=lang, any_language=False
                            )
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

                if org_id_str:
                    enqueue_outbox_event(
                        organization_id=org_id_str,
                        event_type="task.translated",
                        payload=event_payload,
                    )

            scopes = [str(task.user_id)]
            if task.organization_id:
                scopes.append(f"org:{task.organization_id}")
            invalidate_task_caches_for_scopes(scopes, task_id=str(task.id))

            ws_org = org_id_str or "global"
            broadcast_task_websocket_event(ws_org, "translated", event_payload)

            logger.info("Translations generated for task %s", task_id)
            return result

        except AIBudgetExceededError as exc:
            logger.warning(
                "Skipping auto-translation for task %s due to exhausted org AI budget: %s",
                task_id,
                exc,
            )
            return {}
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


@shared_task(bind=True, max_retries=4)
def deliver_webhook_event(
    self: CeleryTask,
    endpoint_id: str,
    event_type: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Deliver a signed outbound webhook event with exponential retry backoff."""
    with rls_bypass():
        try:
            endpoint = WebhookEndpoint.objects.get(id=endpoint_id, is_active=True)
        except WebhookEndpoint.DoesNotExist:
            return {"delivered": False, "reason": "endpoint_inactive_or_missing"}

        delivery = deliver_webhook_sync(endpoint, event_type, payload)
        if not delivery.success and endpoint.is_active:
            backoff = min(300, 15 * (2**self.request.retries))
            raise self.retry(
                exc=RuntimeError(delivery.error_message or "Webhook delivery failed"),
                countdown=backoff,
            )
        return {
            "delivered": delivery.success,
            "delivery_id": str(delivery.id),
            "status": delivery.response_status,
        }


@shared_task
def drain_outbox_events(
    batch_size: int = 50,
    event_id: str | None = None,
) -> dict[str, int]:
    """Drain pending Transactional Outbox events via ``FOR UPDATE SKIP LOCKED``."""
    return drain_outbox_batch(batch_size=batch_size, event_id=event_id)


@shared_task
def prune_telemetry_and_outbox_history(
    outbox_retention_days: int | None = None,
    delivery_retention_days: int | None = None,
    chunk_size: int = 500,
) -> dict[str, int]:
    """Prune aged ``dispatched`` outbox rows and webhook delivery logs in bounded batches."""
    return prune_outbox_and_webhook_history(
        outbox_retention_days=outbox_retention_days,
        delivery_retention_days=delivery_retention_days,
        chunk_size=chunk_size,
    )


@shared_task
def anchor_audit_chain_checkpoints(batch_size: int = 100) -> dict[str, int]:
    """Notarize and S3 Object-Lock WORM anchor pending tenant AuditLog hash chains."""
    from apps.core.audit_chain import anchor_pending_audit_checkpoints

    return anchor_pending_audit_checkpoints(batch_size=batch_size)
