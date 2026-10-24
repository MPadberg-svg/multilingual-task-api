"""Transactional Outbox service with ``SELECT ... FOR UPDATE SKIP LOCKED`` relay.

Persists outbound webhook and pub/sub domain events inside the business database
transaction so rolled-back mutations never emit phantom events and committed
mutations survive temporary Redis/Celery broker outages via asynchronous relay
and periodic Celery Beat sweeps.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from django.conf import settings
from django.db import connection, transaction
from django.db.models import F
from django.utils import timezone

from apps.core.events import EventPublisher
from apps.core.models import OutboxEvent, WebhookDelivery
from apps.core.rls import rls_bypass
from apps.core.tracing import get_current_traceparent, start_span
from apps.core.webhooks import dispatch_organization_webhooks

logger = logging.getLogger(__name__)

MAX_OUTBOX_ATTEMPTS: int = 10
STALE_PROCESSING_SECONDS: int = 300


def trigger_outbox_drain(event_id: str | None = None) -> None:
    """Best-effort immediate Celery relay trigger scheduled via ``transaction.on_commit``."""
    from apps.tasks.tasks import drain_outbox_events

    try:
        drain_outbox_events.delay(batch_size=50, event_id=event_id)
    except Exception:
        logger.warning(
            "Broker unavailable during on_commit outbox trigger (event=%s); "
            "Celery Beat outbox sweep will relay once broker recovers.",
            event_id,
        )


def enqueue_outbox_event(
    *,
    organization_id: str | None,
    event_type: str,
    payload: dict[str, Any],
    topic: str = "webhook",
) -> OutboxEvent | None:
    """Persist an ``OutboxEvent`` in the caller's transaction and schedule post-commit relay."""
    normalized_org_id = (
        str(organization_id) if organization_id and str(organization_id) != "global" else None
    )
    if topic == "webhook" and normalized_org_id is None:
        return None

    traceparent = get_current_traceparent() or ""
    event = OutboxEvent.objects.create(
        organization_id=normalized_org_id,
        topic=topic,
        event_type=event_type,
        payload=payload,
        traceparent=traceparent,
    )
    event_id_str = str(event.id)
    transaction.on_commit(lambda: trigger_outbox_drain(event_id_str))
    return event


def drain_outbox_batch(
    *,
    batch_size: int = 50,
    event_id: str | None = None,
) -> dict[str, int]:
    """Claim pending outbox events with ``FOR UPDATE SKIP LOCKED`` and dispatch them."""
    with rls_bypass():
        now = timezone.now()

        # Reclaim events stuck in 'processing' if a worker crashed mid-flight
        OutboxEvent.objects.filter(
            status="processing",
            next_attempt_at__lte=now,
        ).update(status="pending")

        with transaction.atomic():
            qs = OutboxEvent.objects.filter(
                status="pending",
                next_attempt_at__lte=now,
            )
            if event_id:
                qs = qs.filter(id=event_id)
            qs = qs.order_by("created_at")

            if connection.features.has_select_for_update_skip_locked:
                qs = qs.select_for_update(skip_locked=True)
            elif connection.features.has_select_for_update:
                qs = qs.select_for_update()

            claimed_events = list(qs[: max(1, int(batch_size))])
            if not claimed_events:
                return {"claimed": 0, "dispatched": 0, "retried": 0, "failed": 0}

            claimed_ids = [ev.id for ev in claimed_events]
            OutboxEvent.objects.filter(id__in=claimed_ids).update(
                status="processing",
                attempts=F("attempts") + 1,
                next_attempt_at=now + timedelta(seconds=STALE_PROCESSING_SECONDS),
            )

        dispatched = 0
        retried = 0
        failed = 0

        for ev in claimed_events:
            attempt_number = int(ev.attempts) + 1
            org_scope = str(ev.organization_id) if ev.organization_id else "global"

            with start_span(
                "outbox.dispatch",
                kind="PRODUCER",
                parent_traceparent=ev.traceparent or None,
                attributes={
                    "outbox.id": str(ev.id),
                    "outbox.topic": ev.topic,
                    "outbox.event_type": ev.event_type,
                    "outbox.attempt": attempt_number,
                },
            ) as span:
                try:
                    if ev.topic == "webhook":
                        dispatch_organization_webhooks(
                            str(ev.organization_id) if ev.organization_id else None,
                            ev.event_type,
                            ev.payload,
                            raise_on_broker_error=True,
                        )
                    elif ev.topic == "pubsub":
                        raw_data = ev.payload.get("data")
                        task_data = raw_data if isinstance(raw_data, dict) else dict(ev.payload)
                        action = str(ev.payload.get("action") or ev.event_type)
                        EventPublisher().publish_task_event(
                            org_scope,
                            action,
                            task_data,
                            raise_on_error=True,
                        )
                    else:
                        raise ValueError(f"Unsupported outbox topic '{ev.topic}'")
                except Exception as exc:
                    err_text = str(exc)[:450]
                    span.set_error(err_text)
                    if attempt_number >= MAX_OUTBOX_ATTEMPTS:
                        logger.error(
                            "Outbox event moved to dead-letter: id=%s topic=%s type=%s err=%s",
                            ev.id,
                            ev.topic,
                            ev.event_type,
                            err_text,
                        )
                        OutboxEvent.objects.filter(id=ev.id).update(
                            status="failed",
                            last_error=err_text,
                        )
                        failed += 1
                    else:
                        backoff = min(300, 5 * (2 ** min(attempt_number, 6)))
                        OutboxEvent.objects.filter(id=ev.id).update(
                            status="pending",
                            next_attempt_at=timezone.now() + timedelta(seconds=backoff),
                            last_error=err_text,
                        )
                        retried += 1
                else:
                    OutboxEvent.objects.filter(id=ev.id).update(
                        status="dispatched",
                        dispatched_at=timezone.now(),
                        last_error="",
                    )
                    dispatched += 1

        return {
            "claimed": len(claimed_events),
            "dispatched": dispatched,
            "retried": retried,
            "failed": failed,
        }


def replay_dead_letter_outbox_event(event: OutboxEvent) -> OutboxEvent:
    """Reset a ``failed`` dead-letter ``OutboxEvent`` to ``pending`` and schedule immediate relay."""
    if event.status != "failed":
        raise ValueError(
            f"Only 'failed' outbox events can be replayed (current status: '{event.status}')."
        )

    now = timezone.now()
    with transaction.atomic():
        event.status = "pending"
        event.attempts = 0
        event.next_attempt_at = now
        event.dispatched_at = None
        event.last_error = ""
        event.save(
            update_fields=[
                "status",
                "attempts",
                "next_attempt_at",
                "dispatched_at",
                "last_error",
            ]
        )
        event_id_str = str(event.id)
        transaction.on_commit(lambda: trigger_outbox_drain(event_id_str))

    return event


def prune_outbox_and_webhook_history(
    *,
    outbox_retention_days: int | None = None,
    delivery_retention_days: int | None = None,
    chunk_size: int = 500,
    max_chunks: int = 20,
) -> dict[str, int]:
    """Prune aged ``dispatched`` outbox rows and webhook delivery logs in bounded chunks.

    Never deletes ``pending``, ``processing``, or ``failed`` dead-letter outbox rows.
    """
    resolved_outbox_days = (
        int(outbox_retention_days)
        if outbox_retention_days is not None
        else int(getattr(settings, "OUTBOX_RETENTION_DAYS", 14))
    )
    resolved_delivery_days = (
        int(delivery_retention_days)
        if delivery_retention_days is not None
        else int(getattr(settings, "WEBHOOK_DELIVERY_RETENTION_DAYS", 30))
    )
    safe_chunk = max(1, int(chunk_size))
    safe_max_chunks = max(1, int(max_chunks))

    now = timezone.now()
    outbox_cutoff = now - timedelta(days=max(0, resolved_outbox_days))
    delivery_cutoff = now - timedelta(days=max(0, resolved_delivery_days))

    outbox_deleted = 0
    deliveries_deleted = 0

    with rls_bypass():
        for _ in range(safe_max_chunks):
            batch_ids = list(
                OutboxEvent.objects.filter(
                    status="dispatched",
                    dispatched_at__lte=outbox_cutoff,
                )
                .order_by("dispatched_at")
                .values_list("id", flat=True)[:safe_chunk]
            )
            if not batch_ids:
                break
            deleted_count, _ = OutboxEvent.objects.filter(
                id__in=batch_ids,
                status="dispatched",
            ).delete()
            outbox_deleted += int(deleted_count)
            if len(batch_ids) < safe_chunk:
                break

        for _ in range(safe_max_chunks):
            delivery_ids = list(
                WebhookDelivery.objects.filter(delivered_at__lte=delivery_cutoff)
                .order_by("delivered_at")
                .values_list("id", flat=True)[:safe_chunk]
            )
            if not delivery_ids:
                break
            deleted_count, _ = WebhookDelivery.objects.filter(id__in=delivery_ids).delete()
            deliveries_deleted += int(deleted_count)
            if len(delivery_ids) < safe_chunk:
                break

    return {
        "outbox_deleted": outbox_deleted,
        "deliveries_deleted": deliveries_deleted,
    }
