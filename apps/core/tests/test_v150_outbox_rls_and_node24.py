"""Unit and contract tests for v1.5.0: Transactional Outbox, PostgreSQL RLS, and Node 24 CI."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db import connection, transaction
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

import pytest
import yaml
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.core.events import EventPublisher
from apps.core.models import (
    Organization,
    OrganizationMember,
    OutboxEvent,
    WebhookDelivery,
    WebhookEndpoint,
)
from apps.core.outbox import MAX_OUTBOX_ATTEMPTS, drain_outbox_batch, enqueue_outbox_event
from apps.core.rls import (
    RLSScope,
    _reset_if_dirty,
    _sync_postgres_gucs,
    get_effective_rls_scope,
    rls_bypass,
    rls_context,
)
from apps.tasks.models import Task
from apps.tasks.tasks import deliver_webhook_event, drain_outbox_events

User = get_user_model()

REPO_ROOT = Path(__file__).resolve().parents[3]
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
DEPLOY_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "deploy.yml"


@pytest.mark.django_db
class TestTransactionalOutboxUnit:
    """Verify atomic rollback, broker-outage recovery, trace propagation, and dead-lettering."""

    def test_rolled_back_transaction_leaves_zero_outbox_events_or_phantom_webhooks(self) -> None:
        user = User.objects.create_user(email="rollback-outbox@example.com", password="pw")
        org = Organization.objects.create(name="Rollback Org", slug="rollback-org")
        OrganizationMember.objects.create(user=user, organization=org, role="owner")
        WebhookEndpoint.objects.create(
            organization=org,
            created_by=user,
            url="https://sink.example.org/wh",
            secret="whsec_rollback",
            events=["task.created"],
        )

        with patch("apps.tasks.tasks.deliver_webhook_event.delay") as mock_delay:
            with pytest.raises(RuntimeError, match="abort business tx"):
                with transaction.atomic():
                    task = Task.objects.create(user=user, organization=org, status="pending")
                    enqueue_outbox_event(
                        organization_id=str(org.id),
                        event_type="task.created",
                        payload={"task_id": str(task.id)},
                    )
                    raise RuntimeError("abort business tx")

            assert Task.objects.filter(organization=org).count() == 0
            assert OutboxEvent.objects.filter(organization=org).count() == 0
            mock_delay.assert_not_called()

    def test_pubsub_outbox_retries_with_backoff_reclaims_stale_and_dead_letters(self) -> None:
        user = User.objects.create_user(email="pubsub-outbox@example.com", password="pw")
        org = Organization.objects.create(name="PubSub Org", slug="pubsub-org")

        # 1. Stale 'processing' event is reclaimed and dispatched when Redis succeeds
        stale_ev = OutboxEvent.objects.create(
            organization=org,
            topic="pubsub",
            event_type="updated",
            payload={"action": "updated", "data": {"id": "t-stale", "user_id": str(user.id)}},
            status="processing",
            attempts=1,
            next_attempt_at=timezone.now() - timedelta(seconds=10),
        )
        EventPublisher._instance = None
        fake_pub = EventPublisher()
        fake_pub.redis = MagicMock()

        summary = drain_outbox_batch(batch_size=10, event_id=str(stale_ev.id))
        assert summary == {"claimed": 1, "dispatched": 1, "retried": 0, "failed": 0}
        stale_ev.refresh_from_db()
        assert stale_ev.status == "dispatched"
        assert stale_ev.dispatched_at is not None
        fake_pub.redis.publish.assert_called_once()

        # 2. Failing pubsub publish retries until MAX_OUTBOX_ATTEMPTS, then transitions to 'failed'
        failing_ev = OutboxEvent.objects.create(
            organization=org,
            topic="pubsub",
            event_type="created",
            payload={"action": "created", "data": {"id": "t-fail", "user_id": str(user.id)}},
            status="pending",
            attempts=MAX_OUTBOX_ATTEMPTS - 2,
            next_attempt_at=timezone.now(),
        )
        fake_pub.redis.publish.side_effect = ConnectionError("Redis pubsub socket broken")

        first_try = drain_outbox_batch(batch_size=10, event_id=str(failing_ev.id))
        assert first_try == {"claimed": 1, "dispatched": 0, "retried": 1, "failed": 0}
        failing_ev.refresh_from_db()
        assert failing_ev.status == "pending"
        assert failing_ev.attempts == MAX_OUTBOX_ATTEMPTS - 1
        assert "Redis pubsub socket broken" in failing_ev.last_error

        # Fast-forward backoff window for final attempt -> 'failed' dead-letter state
        OutboxEvent.objects.filter(id=failing_ev.id).update(next_attempt_at=timezone.now())
        final_try = drain_outbox_batch(batch_size=10, event_id=str(failing_ev.id))
        assert final_try == {"claimed": 1, "dispatched": 0, "retried": 0, "failed": 1}
        failing_ev.refresh_from_db()
        assert failing_ev.status == "failed"
        assert failing_ev.attempts == MAX_OUTBOX_ATTEMPTS

        EventPublisher._instance = None

    def test_celery_beat_schedule_registers_transactional_outbox_sweep(self) -> None:
        beat_entry = settings.CELERY_BEAT_SCHEDULE["drain-transactional-outbox"]
        assert beat_entry["task"] == "apps.tasks.tasks.drain_outbox_events"
        assert float(beat_entry["schedule"]) <= 30.0


@pytest.mark.django_db(transaction=True)
def test_outbox_survives_broker_outage_and_relays_with_w3c_traceparent() -> None:
    """
    Simulate a Redis/Celery broker outage during POST /api/v1/tasks/:
    1. API still returns HTTP 201 and persists the OutboxEvent with the caller's W3C traceparent.
    2. Once the broker recovers, drain_outbox_events() dispatches the signed webhook and
       propagates the exact originating 32-hex trace_id to the remote HTTP sink.
    """
    cache.clear()
    user = User.objects.create_user(email="broker-outage@example.com", password="pw")
    org = Organization.objects.create(name="Outage Org", slug="outage-org", max_tasks=50)
    OrganizationMember.objects.create(user=user, organization=org, role="owner")
    endpoint = WebhookEndpoint.objects.create(
        organization=org,
        created_by=user,
        url="https://sink.example.org/outbox",
        secret="whsec_outbox_trace",
        events=["task.created"],
    )

    token = str(RefreshToken.for_user(user).access_token)
    incoming_trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"
    incoming_tp = f"00-{incoming_trace_id}-00f067aa0ba902b7-01"

    client = APIClient()
    client.credentials(
        HTTP_AUTHORIZATION=f"Bearer {token}",
        HTTP_X_ORGANIZATION_ID=str(org.id),
        HTTP_TRACEPARENT=incoming_tp,
    )

    with patch(
        "apps.tasks.tasks.deliver_webhook_event.delay",
        side_effect=ConnectionError("Celery Redis broker down"),
    ):
        resp = client.post(
            "/api/v1/tasks/",
            {"title": "Outbox durable task", "description": "Must survive broker blip"},
            format="json",
        )
        assert resp.status_code == 201

    outbox_ev = OutboxEvent.objects.get(organization=org, event_type="task.created")
    assert outbox_ev.status == "pending"
    assert outbox_ev.attempts == 1
    assert "Celery Redis broker down" in outbox_ev.last_error
    assert incoming_trace_id in outbox_ev.traceparent

    # Fast-forward retry timer and simulate broker + HTTPS sink recovery
    OutboxEvent.objects.filter(id=outbox_ev.id).update(next_attempt_at=timezone.now())

    captured_headers: dict[str, str] = {}
    fake_http_resp = MagicMock(status=200)
    fake_conn = MagicMock()
    fake_conn.getresponse.return_value = fake_http_resp

    def _capture_request(method: str, path: str, body: bytes, headers: dict[str, str]) -> None:
        captured_headers.update(headers)

    fake_conn.request.side_effect = _capture_request

    with (
        patch("apps.core.webhooks.validate_webhook_url", side_effect=lambda u, **kw: u),
        patch("apps.core.webhooks.http.client.HTTPSConnection", return_value=fake_conn),
        patch(
            "apps.tasks.tasks.deliver_webhook_event.delay",
            side_effect=lambda ep_id, ev_type, pl: deliver_webhook_event(ep_id, ev_type, pl),
        ),
    ):
        relay_res = drain_outbox_events(batch_size=10, event_id=str(outbox_ev.id))

    assert relay_res["dispatched"] == 1
    outbox_ev.refresh_from_db()
    assert outbox_ev.status == "dispatched"
    assert outbox_ev.dispatched_at is not None
    assert outbox_ev.last_error == ""

    delivery = WebhookDelivery.objects.get(endpoint=endpoint, event_type="task.created")
    assert delivery.success is True
    assert incoming_trace_id in captured_headers.get("traceparent", "")


class TestPostgresRLSScopeAndAuthDedup:
    """Verify nested RLS context transitions, PostgreSQL GUC memoization, and JWT dedup."""

    def test_nested_rls_context_and_postgres_guc_memoization_and_inerror_safety(self) -> None:
        assert get_effective_rls_scope() == RLSScope()

        with rls_context(organization_id="org-1", user_id="user-1") as outer_scope:
            assert outer_scope.as_guc_tuple() == ("on", "org-1", "user-1", "")
            assert get_effective_rls_scope() == outer_scope

            with rls_context(organization_id="org-2", user_id="user-1") as inner_scope:
                assert inner_scope.as_guc_tuple() == ("on", "org-2", "user-1", "")
                assert get_effective_rls_scope() == inner_scope

                with rls_bypass() as bypass_scope:
                    assert bypass_scope.as_guc_tuple() == ("", "", "", "on")
                    assert get_effective_rls_scope() == bypass_scope

                assert get_effective_rls_scope() == inner_scope

            assert get_effective_rls_scope() == outer_scope

        assert get_effective_rls_scope() == RLSScope()

        # Verify fake PostgreSQL driver connection memoization & INERROR transaction handling
        executed_params: list[tuple[str, str, str, str]] = []

        class _FakeRawCursor:
            def __enter__(self) -> "_FakeRawCursor":
                return self

            def __exit__(self, *args: Any) -> None:
                return None

            def execute(self, _sql: str, params: tuple[str, str, str, str]) -> None:
                executed_params.append(params)

        class _FakeInfo:
            transaction_status = 0

        class _FakeRawConn:
            closed = 0
            info = _FakeInfo()

            def cursor(self) -> _FakeRawCursor:
                return _FakeRawCursor()

        class _FakeDjangoPGConn:
            vendor = "postgresql"
            connection = _FakeRawConn()

        pg_conn = _FakeDjangoPGConn()
        target = ("on", "org-abc", "user-xyz", "")
        _sync_postgres_gucs(pg_conn, target)
        _sync_postgres_gucs(pg_conn, target)  # Memoized: must NOT execute a duplicate query
        assert executed_params == [target]

        # Simulate aborted transaction (TRANSACTION_STATUS_INERROR == 3)
        pg_conn.connection.info.transaction_status = 3
        _sync_postgres_gucs(pg_conn, ("on", "org-other", "user-xyz", ""))
        assert len(executed_params) == 1
        assert getattr(pg_conn, "_mltask_rls_state") is None

        # Once rolled back to healthy status (0), _sync & _reset_if_dirty succeed cleanly
        pg_conn.connection.info.transaction_status = 0
        _sync_postgres_gucs(pg_conn, target)
        _reset_if_dirty(pg_conn)
        assert executed_params[-1] == ("", "", "", "")

    @pytest.mark.django_db
    def test_cached_jwt_authentication_deduplicates_user_lookup_and_preserves_openapi(self) -> None:
        cache.clear()
        user = User.objects.create_user(email="jwt-dedup@example.com", password="pw")
        task = Task.objects.create(user=user, status="pending")
        task.set_current_language("en")
        task.title = "Single JWT user lookup"
        task.save()

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {RefreshToken.for_user(user).access_token}")

        with CaptureQueriesContext(connection) as ctx:
            resp = client.get("/api/v1/tasks/")
        assert resp.status_code == 200
        user_queries = [q for q in ctx.captured_queries if 'FROM "core_user"' in q["sql"]]
        assert len(user_queries) == 1
        assert len(ctx) <= 4

        schema_resp = client.get("/api/schema/?format=json")
        assert schema_resp.status_code == 200
        sec_schemes = schema_resp.json()["components"]["securitySchemes"]
        assert "jwtAuth" in sec_schemes
        assert "OrganizationApiKeyAuth" in sec_schemes


def test_github_workflows_modernized_to_node24_actions() -> None:
    """Verify CI and deploy workflows contain zero deprecated Node 20 action pins."""
    deprecated_pins = {
        "actions/checkout@v4",
        "actions/setup-python@v5",
        "actions/upload-artifact@v4",
        "hashicorp/setup-terraform@v3",
        "aws-actions/configure-aws-credentials@v4",
    }
    for wf_path in (CI_WORKFLOW, DEPLOY_WORKFLOW):
        raw_text = wf_path.read_text(encoding="utf-8")
        for pin in deprecated_pins:
            assert pin not in raw_text, f"{wf_path.name} still references deprecated {pin}"

        parsed = yaml.safe_load(raw_text)
        for job_name, job in parsed["jobs"].items():
            for step in job.get("steps", []):
                uses = step.get("uses", "")
                if uses.startswith("actions/checkout@"):
                    assert uses == "actions/checkout@v6", f"{job_name}: {uses}"
                elif uses.startswith("actions/setup-python@"):
                    assert uses == "actions/setup-python@v6", f"{job_name}: {uses}"
                elif uses.startswith("hashicorp/setup-terraform@"):
                    assert uses == "hashicorp/setup-terraform@v4", f"{job_name}: {uses}"
                elif uses.startswith("aws-actions/configure-aws-credentials@"):
                    assert uses == "aws-actions/configure-aws-credentials@v6", f"{job_name}: {uses}"
