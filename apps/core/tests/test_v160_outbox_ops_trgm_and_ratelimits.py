"""Unit and contract tests for v1.6.0: Outbox Ops/Pruning, pg_trgm Search, and Org Rate Limits."""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import MagicMock, patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.utils import timezone

import pytest
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.core.models import (
    AuditLog,
    Organization,
    OrganizationMember,
    OutboxEvent,
    WebhookDelivery,
    WebhookEndpoint,
)
from apps.core.throttling import OrganizationPlanRateThrottle
from apps.tasks.filters import TaskFilter
from apps.tasks.models import Task
from apps.tasks.tasks import deliver_webhook_event, prune_telemetry_and_outbox_history

User = get_user_model()


def _auth_client(user: object, org: Organization | None = None) -> APIClient:
    token = str(RefreshToken.for_user(user).access_token)  # type: ignore[arg-type]
    client = APIClient()
    creds: dict[str, str] = {"HTTP_AUTHORIZATION": f"Bearer {token}"}
    if org is not None:
        creds["HTTP_X_ORGANIZATION_ID"] = str(org.id)
    client.credentials(**creds)
    return client


@pytest.mark.django_db(transaction=True)
def test_outbox_inspector_and_dead_letter_replay_endpoint_with_audit_trail() -> None:
    """
    Verify:
    1. GET /api/v1/organizations/{org_id}/outbox/?status=failed lists dead-letter rows for admins
       and rejects non-admin contributors with 403.
    2. POST .../outbox/{id}/replay/ rejects non-failed rows with 409 Conflict.
    3. POST .../outbox/{failed_id}/replay/ resets attempts, relays & delivers the signed webhook,
       transitions status -> 'dispatched', and records an immutable AuditLog entry.
    """
    cache.clear()
    owner = User.objects.create_user(email="outbox-ops-owner@example.com", password="pw")
    contrib = User.objects.create_user(email="outbox-ops-contrib@example.com", password="pw")
    org = Organization.objects.create(name="Outbox Ops Org", slug="outbox-ops-org", max_users=10)
    OrganizationMember.objects.create(user=owner, organization=org, role="owner")
    OrganizationMember.objects.create(user=contrib, organization=org, role="contributor")

    endpoint = WebhookEndpoint.objects.create(
        organization=org,
        created_by=owner,
        url="https://sink.example.org/dlq",
        secret="whsec_dlq_replay_secret",
        events=["task.completed"],
    )
    dispatched_ev = OutboxEvent.objects.create(
        organization=org,
        topic="webhook",
        event_type="task.completed",
        payload={"task_id": "t-already-ok"},
        status="dispatched",
        dispatched_at=timezone.now(),
    )
    dead_letter_ev = OutboxEvent.objects.create(
        organization=org,
        topic="webhook",
        event_type="task.completed",
        payload={"task_id": "t-dlq-1"},
        status="failed",
        attempts=10,
        last_error="Remote sink timed out 10 times",
    )

    contrib_client = _auth_client(contrib)
    assert contrib_client.get(f"/api/v1/organizations/{org.id}/outbox/").status_code == 403

    owner_client = _auth_client(owner)
    list_resp = owner_client.get(
        f"/api/v1/organizations/{org.id}/outbox/?status=failed&topic=webhook"
    )
    assert list_resp.status_code == 200
    assert list_resp.json()["count"] == 1
    assert list_resp.json()["results"][0]["id"] == str(dead_letter_ev.id)

    conflict_resp = owner_client.post(
        f"/api/v1/organizations/{org.id}/outbox/{dispatched_ev.id}/replay/"
    )
    assert conflict_resp.status_code == 409

    fake_http_resp = MagicMock(status=200)
    fake_conn = MagicMock()
    fake_conn.getresponse.return_value = fake_http_resp

    with (
        patch("apps.core.webhooks.validate_webhook_url", side_effect=lambda u, **kw: u),
        patch("apps.core.webhooks.http.client.HTTPSConnection", return_value=fake_conn),
        patch(
            "apps.tasks.tasks.deliver_webhook_event.delay",
            side_effect=lambda ep_id, ev_type, pl: deliver_webhook_event(ep_id, ev_type, pl),
        ),
    ):
        replay_resp = owner_client.post(
            f"/api/v1/organizations/{org.id}/outbox/{dead_letter_ev.id}/replay/"
        )

    assert replay_resp.status_code == 200
    assert replay_resp.json()["status"] == "dispatched"
    assert WebhookDelivery.objects.filter(endpoint=endpoint, success=True).count() == 1
    assert (
        AuditLog.objects.filter(
            organization=org,
            action="outbox_replayed",
            resource_id=str(dead_letter_ev.id),
        ).count()
        == 1
    )


@pytest.mark.django_db
def test_bounded_chunk_retention_prunes_aged_dispatched_rows_preserving_dead_letters() -> None:
    """Aged dispatched outbox & webhook delivery rows are pruned in chunks; DLQ rows survive."""
    owner = User.objects.create_user(email="prune-owner@example.com", password="pw")
    org = Organization.objects.create(name="Prune Org", slug="prune-org")
    ep = WebhookEndpoint.objects.create(
        organization=org,
        created_by=owner,
        url="https://sink.example.org/prune",
        secret="whsec_prune_secret",
        events=["task.created"],
    )

    now = timezone.now()
    aged_dispatched_1 = OutboxEvent.objects.create(
        organization=org,
        event_type="task.created",
        status="dispatched",
        dispatched_at=now - timedelta(days=20),
    )
    aged_dispatched_2 = OutboxEvent.objects.create(
        organization=org,
        event_type="task.created",
        status="dispatched",
        dispatched_at=now - timedelta(days=16),
    )
    fresh_dispatched = OutboxEvent.objects.create(
        organization=org,
        event_type="task.created",
        status="dispatched",
        dispatched_at=now - timedelta(days=2),
    )
    aged_dead_letter = OutboxEvent.objects.create(
        organization=org,
        event_type="task.created",
        status="failed",
        attempts=10,
    )
    aged_pending = OutboxEvent.objects.create(
        organization=org,
        event_type="task.created",
        status="pending",
    )

    aged_deliv = WebhookDelivery.objects.create(
        endpoint=ep,
        event_type="task.created",
        payload={},
        response_status=200,
        success=True,
    )
    fresh_deliv = WebhookDelivery.objects.create(
        endpoint=ep,
        event_type="task.created",
        payload={},
        response_status=200,
        success=True,
    )
    WebhookDelivery.objects.filter(id=aged_deliv.id).update(delivered_at=now - timedelta(days=45))

    result = prune_telemetry_and_outbox_history(
        outbox_retention_days=14,
        delivery_retention_days=30,
        chunk_size=1,
    )
    assert result == {"outbox_deleted": 2, "deliveries_deleted": 1}

    remaining_outbox_ids = set(OutboxEvent.objects.values_list("id", flat=True))
    assert aged_dispatched_1.id not in remaining_outbox_ids
    assert aged_dispatched_2.id not in remaining_outbox_ids
    assert fresh_dispatched.id in remaining_outbox_ids
    assert aged_dead_letter.id in remaining_outbox_ids
    assert aged_pending.id in remaining_outbox_ids

    remaining_deliv_ids = set(WebhookDelivery.objects.values_list("id", flat=True))
    assert aged_deliv.id not in remaining_deliv_ids
    assert fresh_deliv.id in remaining_deliv_ids

    beat_cfg = settings.CELERY_BEAT_SCHEDULE["prune-outbox-and-webhook-history"]
    assert beat_cfg["task"] == "apps.tasks.tasks.prune_telemetry_and_outbox_history"


@pytest.mark.django_db
class TestPlanTieredRateLimitingAndWebhookRecovery:
    """Verify per-organization plan rate limits, X-RateLimit headers, and webhook recovery/replay."""

    def test_organization_plan_rate_throttle_enforces_tiers_and_emits_headers(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cache.clear()
        monkeypatch.setitem(OrganizationPlanRateThrottle.THROTTLE_RATES, "org_free", "2/min")
        monkeypatch.setitem(OrganizationPlanRateThrottle.THROTTLE_RATES, "org_enterprise", "50/min")

        user = User.objects.create_user(email="ratelimit@example.com", password="pw")
        free_org = Organization.objects.create(name="Free RL Org", slug="free-rl-org", plan="free")
        ent_org = Organization.objects.create(
            name="Ent RL Org", slug="ent-rl-org", plan="enterprise"
        )
        OrganizationMember.objects.create(user=user, organization=free_org, role="owner")
        OrganizationMember.objects.create(user=user, organization=ent_org, role="owner")

        free_client = _auth_client(user, free_org)
        r1 = free_client.get("/api/v1/tasks/")
        assert r1.status_code == 200
        assert r1["X-RateLimit-Plan"] == "free"
        assert r1["X-RateLimit-Limit"] == "2"
        assert r1["X-RateLimit-Remaining"] == "1"

        r2 = free_client.get("/api/v1/tasks/")
        assert r2.status_code == 200
        assert r2["X-RateLimit-Remaining"] == "0"

        r3 = free_client.get("/api/v1/tasks/")
        assert r3.status_code == 429
        assert r3["X-RateLimit-Remaining"] == "0"
        assert "Retry-After" in r3

        # Separate enterprise tenant remains completely unthrottled on its 50/min tier
        ent_client = _auth_client(user, ent_org)
        r_ent = ent_client.get("/api/v1/tasks/")
        assert r_ent.status_code == 200
        assert r_ent["X-RateLimit-Plan"] == "enterprise"
        assert r_ent["X-RateLimit-Limit"] == "50"

        # Personal non-org request does not carry X-RateLimit-Plan
        personal_client = _auth_client(user, None)
        r_personal = personal_client.get("/api/v1/tasks/")
        assert r_personal.status_code == 200
        assert "X-RateLimit-Plan" not in r_personal

    def test_webhook_circuit_recover_delivery_history_and_delivery_replay(self) -> None:
        cache.clear()
        owner = User.objects.create_user(email="wh-ops@example.com", password="pw")
        org = Organization.objects.create(name="WH Ops Org", slug="wh-ops-org")
        OrganizationMember.objects.create(user=owner, organization=org, role="owner")

        endpoint = WebhookEndpoint.objects.create(
            organization=org,
            created_by=owner,
            url="https://sink.example.org/events",
            secret="whsec_recover_and_replay_secret",
            events=["task.completed"],
            is_active=False,
            failure_count=10,
        )
        failed_delivery = WebhookDelivery.objects.create(
            endpoint=endpoint,
            event_type="task.completed",
            payload={
                "id": "orig-deliv",
                "event": "task.completed",
                "data": {"task_id": "task-replay-777", "status": "completed"},
            },
            response_status=503,
            success=False,
            error_message="Non-2xx HTTP status 503",
        )

        client = _auth_client(owner)

        # 1. Inspect failed deliveries
        hist_resp = client.get(
            f"/api/v1/organizations/{org.id}/webhooks/{endpoint.id}/deliveries/?success=false&event_type=task.completed"
        )
        assert hist_resp.status_code == 200
        assert hist_resp.json()["count"] == 1
        assert hist_resp.json()["results"][0]["id"] == str(failed_delivery.id)

        # 2. Recover auto-disabled circuit-broken endpoint
        rec_resp = client.post(f"/api/v1/organizations/{org.id}/webhooks/{endpoint.id}/recover/")
        assert rec_resp.status_code == 200
        endpoint.refresh_from_db()
        assert endpoint.is_active is True
        assert endpoint.failure_count == 0
        assert AuditLog.objects.filter(organization=org, action="webhook_recovered").count() == 1

        # 3. Replay historical failed delivery with fresh HMAC signature
        sent_bodies: list[bytes] = []
        fake_http_resp = MagicMock(status=202)
        fake_conn = MagicMock()
        fake_conn.getresponse.return_value = fake_http_resp
        fake_conn.request.side_effect = lambda _m, _p, body, headers: sent_bodies.append(body)

        with (
            patch("apps.core.webhooks.validate_webhook_url", side_effect=lambda u, **kw: u),
            patch("apps.core.webhooks.http.client.HTTPSConnection", return_value=fake_conn),
        ):
            replay_resp = client.post(
                f"/api/v1/organizations/{org.id}/webhooks/{endpoint.id}/deliveries/{failed_delivery.id}/replay/"
            )

        assert replay_resp.status_code == 200
        assert replay_resp.json()["success"] is True
        assert replay_resp.json()["response_status"] == 202
        assert replay_resp.json()["id"] != str(failed_delivery.id)
        assert b"task-replay-777" in sent_bodies[0]
        assert AuditLog.objects.filter(organization=org, action="webhook_replayed").count() == 1


@pytest.mark.django_db
def test_trigram_search_semi_join_escapes_wildcards_and_avoids_distinct_fanout() -> None:
    """TaskFilter(search=...) uses an EXISTS semi-join and escapes literal % and _ wildcards."""
    user = User.objects.create_user(email="trgm-unit@example.com", password="pw")
    t_match = Task.objects.create(user=user, status="pending")
    t_match.set_current_language("es")
    t_match.title = "Precisión 100%_RLHF verificada"
    t_match.save()

    t_decoy = Task.objects.create(user=user, status="pending")
    t_decoy.set_current_language("es")
    t_decoy.title = "Precisión 100XXYRLHF falso"
    t_decoy.save()

    filtered = TaskFilter({"search": "100%_rlhf"}, queryset=Task.objects.all()).qs
    sql = str(filtered.query)
    assert "EXISTS" in sql
    assert "DISTINCT" not in sql

    matched_ids = [str(pk) for pk in filtered.values_list("id", flat=True)]
    assert matched_ids == [str(t_match.id)]
