"""Live PostgreSQL 16 & Redis 7 integration tests.

Exercises real ``SELECT ... FOR UPDATE SKIP LOCKED LIMIT 1`` multi-connection
concurrency, ``django-redis`` ``ZlibCompressor`` + ``INCRBY`` wire operations,
Redis Pub/Sub ``EventPublisher`` delivery, and ``channels-redis`` WebSockets.
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db import DatabaseError, connections, transaction
from django.db.models import Q

import pytest
from asgiref.sync import sync_to_async
from channels.layers import get_channel_layer
from channels.testing import WebsocketCommunicator
from django_redis import get_redis_connection
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

from apps.core.events import EventPublisher, broadcast_task_websocket_event
from apps.core.models import Organization, OrganizationMember, OutboxEvent, WebhookEndpoint
from apps.core.outbox import drain_outbox_batch
from apps.core.rls import rls_context
from apps.core.views import record_ai_token_usage
from apps.tasks.models import Task
from config.asgi import application

User = get_user_model()

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        settings.DATABASES["default"]["ENGINE"] != "django.db.backends.postgresql",
        reason="Requires live PostgreSQL 16 + Redis 7 (--ds=config.settings.ci_integration)",
    ),
]


def _make_org_annotator(org: Organization, idx: int) -> tuple[object, APIClient]:
    user = User.objects.create_user(
        email=f"pg-annotator-{idx}-{int(time.time() * 1000)}@example.com",
        password="testpass123",
    )
    OrganizationMember.objects.create(
        user=user,
        organization=org,
        role="contributor",
    )
    token = str(RefreshToken.for_user(user).access_token)
    client = APIClient()
    client.credentials(
        HTTP_AUTHORIZATION=f"Bearer {token}",
        HTTP_X_ORGANIZATION_ID=str(org.id),
    )
    return user, client


@pytest.mark.django_db(transaction=True)
def test_postgres_skip_locked_skips_in_flight_row_without_blocking_or_starvation() -> None:
    """
    Hold an uncommitted PostgreSQL FOR UPDATE row lock on the highest-priority task
    in a background thread and verify that a second annotator calling /tasks/claim/
    immediately skips the locked row and claims the next task (HTTP 200) instead of
    blocking on the lock or falsely receiving HTTP 204.
    """
    cache.clear()
    owner = User.objects.create_user(email="pg-owner-skip@example.com", password="pw")
    org = Organization.objects.create(name="PG Skip Org", slug="pg-skip-org")
    OrganizationMember.objects.create(user=owner, organization=org, role="owner")

    critical_task = Task.objects.create(
        user=owner,
        organization=org,
        priority="critical",
        status="pending",
        required_annotations=2,
    )
    critical_task.set_current_language("en")
    critical_task.title = "Critical Locked Task"
    critical_task.description = "Held open in Connection A"
    critical_task.save()

    high_task = Task.objects.create(
        user=owner,
        organization=org,
        priority="high",
        status="pending",
        required_annotations=2,
    )
    high_task.set_current_language("en")
    high_task.title = "High Unlocked Task"
    high_task.description = "Should be claimed immediately by Connection B"
    high_task.save()

    _, client_b = _make_org_annotator(org, 1)

    row_locked = threading.Event()
    release_lock = threading.Event()

    def hold_row_lock() -> None:
        try:
            with transaction.atomic():
                locked = Task.objects.filter(pk=critical_task.pk).select_for_update().first()
                assert locked is not None
                row_locked.set()
                release_lock.wait(timeout=10.0)
        finally:
            connections.close_all()

    holder = threading.Thread(target=hold_row_lock, daemon=True)
    holder.start()
    assert row_locked.wait(timeout=5.0) is True

    try:
        started = time.perf_counter()
        resp = client_b.post("/api/v1/tasks/claim/", {"lease_seconds": 300}, format="json")
        elapsed = time.perf_counter() - started

        assert resp.status_code == 200
        assert resp.json()["id"] == str(high_task.id)
        assert elapsed < 2.0
    finally:
        release_lock.set()
        holder.join(timeout=5.0)


@pytest.mark.django_db(transaction=True)
def test_postgres_concurrent_annotator_stampede_assigns_disjoint_leases() -> None:
    """
    8 concurrent annotators racing through a Barrier against 4 pending tasks on
    PostgreSQL 16 must produce exactly 4 disjoint HTTP 200 leases and 4 HTTP 204
    responses with zero duplicate claims or database errors.
    """
    cache.clear()
    owner = User.objects.create_user(email="pg-stampede-owner@example.com", password="pw")
    org = Organization.objects.create(
        name="PG Stampede Org",
        slug="pg-stampede-org",
        plan="enterprise",
        max_users=50,
    )
    OrganizationMember.objects.create(user=owner, organization=org, role="owner")

    expected_ids: set[str] = set()
    for idx in range(4):
        task = Task.objects.create(
            user=owner,
            organization=org,
            priority="high",
            status="pending",
            required_annotations=2,
        )
        task.set_current_language("en")
        task.title = f"Stampede Task {idx}"
        task.description = "Concurrent SKIP LOCKED verification"
        task.save()
        expected_ids.add(str(task.id))

    annotators = [_make_org_annotator(org, idx) for idx in range(8)]
    barrier = threading.Barrier(8)

    def claim_worker(entry: tuple[object, APIClient]) -> tuple[int, str | None]:
        _, api_client = entry
        try:
            barrier.wait(timeout=5.0)
            res = api_client.post("/api/v1/tasks/claim/", {"lease_seconds": 300}, format="json")
            task_id = res.json()["id"] if res.status_code == 200 else None
            return res.status_code, task_id
        finally:
            connections.close_all()

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(claim_worker, annotators))

    claimed = [tid for code, tid in outcomes if code == 200 and tid is not None]
    empty = [code for code, _ in outcomes if code == 204]

    assert len(claimed) == 4
    assert len(empty) == 4
    assert set(claimed) == expected_ids


@pytest.mark.django_db
def test_live_redis_zlib_compression_atomic_counters_idempotency_and_probes() -> None:
    """
    Verify live Redis 7 wire behavior: PING, ZlibCompressor + JSONSerializer payload
    round-trip, atomic INCRBY FinOps counters, Idempotency-Key replay, and /health/ + /ready/.
    """
    cache.clear()
    raw_redis = get_redis_connection("default")
    assert raw_redis.ping() is True

    # Large nested dict exercises ZlibCompressor + JSONSerializer over real Redis
    large_payload = {"translations": {f"k{i}": " multitenant-rlhf " * 20 for i in range(25)}}
    cache.set("integration:zlib:roundtrip", large_payload, timeout=60)
    assert cache.get("integration:zlib:roundtrip") == large_payload

    owner = User.objects.create_user(email="redis-finops@example.com", password="pw", is_staff=True)
    org = Organization.objects.create(name="Redis FinOps Org", slug="redis-finops-org")
    OrganizationMember.objects.create(user=owner, organization=org, role="owner")

    # Atomic INCRBY counters on real Redis (must stay integer-encoded even with ZlibCompressor)
    record_ai_token_usage(1200, 400, str(org.id))
    record_ai_token_usage(800, 100, str(org.id))

    client = APIClient()
    token = str(RefreshToken.for_user(owner).access_token)
    client.credentials(
        HTTP_AUTHORIZATION=f"Bearer {token}",
        HTTP_X_ORGANIZATION_ID=str(org.id),
    )

    health = client.get("/api/v1/health/")
    assert health.status_code == 200
    assert health.json()["checks"]["db"]["status"] == "ok"
    assert health.json()["checks"]["redis"]["status"] == "ok"

    ready = client.get("/api/v1/ready/")
    assert ready.status_code == 200
    assert ready.json()["status"] == "ready"

    usage = client.get(f"/api/v1/organizations/{org.id}/usage/")
    assert usage.status_code == 200
    ai_telemetry = usage.json()["ai_telemetry"]
    assert ai_telemetry["requests_total"] == 2
    assert ai_telemetry["prompt_tokens_total"] == 2000
    assert ai_telemetry["completion_tokens_total"] == 500

    # Idempotency-Key SET NX lock + JSON response replay in real Redis
    idem_headers = {"HTTP_IDEMPOTENCY_KEY": "pg-redis-idem-001"}
    r1 = client.post(
        "/api/v1/tasks/",
        {"title": "Redis Idempotent Task", "description": "Stored in PG16"},
        format="json",
        **idem_headers,
    )
    assert r1.status_code == 201
    r2 = client.post(
        "/api/v1/tasks/",
        {"title": "Redis Idempotent Task", "description": "Stored in PG16"},
        format="json",
        **idem_headers,
    )
    assert r2.status_code == 201
    assert r2["X-Idempotency-Replayed"] == "true"
    assert r1.json()["id"] == r2.json()["id"]


@pytest.mark.asyncio
@pytest.mark.django_db(transaction=True)
async def test_live_redis_pubsub_and_channels_redis_websocket_broadcast() -> None:
    """
    Verify real Redis Pub/Sub delivery via EventPublisher AND end-to-end WebSocket
    group broadcast over channels_redis.core.RedisChannelLayer.
    """
    EventPublisher._instance = None
    raw_redis = get_redis_connection("default")
    pubsub = raw_redis.pubsub()

    user = await sync_to_async(User.objects.create_user)(
        email="ws-redis-live@example.com",
        password="pw",
    )
    org = await sync_to_async(Organization.objects.create)(
        name="WS Redis Org",
        slug="ws-redis-org",
    )
    await sync_to_async(OrganizationMember.objects.create)(
        user=user,
        organization=org,
        role="owner",
    )

    channel_name = f"mltask:events:{org.id}:tasks"
    pubsub.subscribe(channel_name)
    try:
        # Wait for explicit SUBSCRIBE ack on this socket before publishing on another connection
        for _ in range(10):
            ack = pubsub.get_message(timeout=0.2)
            if ack and ack.get("type") == "subscribe":
                break

        # Trigger EventPublisher -> real Redis PUBLISH
        await sync_to_async(EventPublisher().publish_task_event)(
            str(org.id),
            "created",
            {"id": "11111111-1111-1111-1111-111111111111", "user_id": str(user.id)},
        )
        msg = None
        for _ in range(15):
            candidate = pubsub.get_message(timeout=0.2)
            if candidate and candidate.get("type") == "message":
                msg = candidate
                break
        assert msg is not None
        decoded = json.loads(
            msg["data"].decode("utf-8") if isinstance(msg["data"], bytes) else msg["data"]
        )
        assert decoded["action"] == "created"
    finally:
        pubsub.unsubscribe(channel_name)
        pubsub.close()

    # Verify live channels_redis WebSocket consumer group delivery
    channel_layer = get_channel_layer()
    assert channel_layer is not None
    assert "RedisChannelLayer" in type(channel_layer).__name__

    jwt_token = str(AccessToken.for_user(user))
    communicator = WebsocketCommunicator(application, f"/ws/tasks/{org.id}/?token={jwt_token}")
    connected, _ = await communicator.connect()
    assert connected is True
    try:
        await sync_to_async(broadcast_task_websocket_event)(
            str(org.id),
            "updated",
            {
                "id": "22222222-2222-2222-2222-222222222222",
                "status": "in_progress",
                "user_id": str(user.id),
            },
        )
        received_actions: list[str] = []
        for _ in range(3):
            frame = await communicator.receive_json_from(timeout=3.0)
            action_val = frame.get("data", {}).get("action") or frame.get("type")
            if action_val:
                received_actions.append(str(action_val))
            if "updated" in received_actions:
                break
        assert "updated" in received_actions
    finally:
        await communicator.disconnect()
        await channel_layer.flush()


@pytest.mark.django_db(transaction=True)
def test_postgres_rls_enforces_storage_layer_tenant_isolation_under_nobypassrls_role() -> None:
    """
    Switch into PostgreSQL's non-superuser NOBYPASSRLS role (mltask_rls_app) and verify
    that UNFILTERED ORM queries and raw SQL INSERTs are physically isolated per tenant
    by PostgreSQL 16 Row-Level Security policies.
    """
    owner_a = User.objects.create_user(email="rls-owner-a@example.com", password="pw")
    org_a = Organization.objects.create(name="RLS Org A", slug="rls-org-a")
    OrganizationMember.objects.create(user=owner_a, organization=org_a, role="owner")
    task_a = Task.objects.create(user=owner_a, organization=org_a, status="pending")
    wh_a = WebhookEndpoint.objects.create(
        organization=org_a,
        created_by=owner_a,
        url="https://a.example.org/wh",
        secret="whsec_rls_a",
        events=["task.created"],
    )

    owner_b = User.objects.create_user(email="rls-owner-b@example.com", password="pw")
    org_b = Organization.objects.create(name="RLS Org B", slug="rls-org-b")
    OrganizationMember.objects.create(user=owner_b, organization=org_b, role="owner")
    task_b = Task.objects.create(user=owner_b, organization=org_b, status="pending")
    wh_b = WebhookEndpoint.objects.create(
        organization=org_b,
        created_by=owner_b,
        url="https://b.example.org/wh",
        secret="whsec_rls_b",
        events=["task.created"],
    )

    personal_task_a = Task.objects.create(user=owner_a, organization=None, status="pending")

    conn = connections["default"]
    with transaction.atomic():
        with conn.cursor() as cur:
            cur.execute("SET LOCAL ROLE mltask_rls_app")
            cur.execute(
                "SELECT current_user, rolsuper, rolbypassrls "
                "FROM pg_roles WHERE rolname = current_user"
            )
            role_row = cur.fetchone()
            assert role_row == ("mltask_rls_app", False, False)

        # 1. Scoped to Org A: unfiltered Task.objects.all() & WebhookEndpoint.objects.all()
        #    MUST return strictly Org A rows (hiding Org B AND personal non-org tasks)
        with rls_context(organization_id=str(org_a.id), user_id=str(owner_a.id)):
            visible_tasks = {str(pk) for pk in Task.objects.values_list("id", flat=True)}
            assert str(task_a.id) in visible_tasks
            assert str(task_b.id) not in visible_tasks
            assert str(personal_task_a.id) not in visible_tasks

            visible_webhooks = {
                str(pk) for pk in WebhookEndpoint.objects.values_list("id", flat=True)
            }
            assert str(wh_a.id) in visible_webhooks
            assert str(wh_b.id) not in visible_webhooks

            # Cross-tenant raw INSERT into Org B while bound to Org A must be rejected by PG16 RLS
            with pytest.raises(DatabaseError):
                with transaction.atomic():
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO tasks_task (
                                id, user_id, organization_id, status, priority,
                                required_annotations, consensus_choice, is_active,
                                created_at, updated_at
                            )
                            VALUES (%s, %s, %s, 'pending', 'medium', 3, '', true, NOW(), NOW())
                            """,
                            [str(uuid.uuid4()), str(owner_a.id), str(org_b.id)],
                        )

        # 2. Unauthenticated enforced scope sees zero rows across protected tables
        with rls_context(organization_id=None, user_id=None, enforced=True):
            assert Task.objects.count() == 0
            assert WebhookEndpoint.objects.count() == 0

        # 3. User-scoped (no X-Organization-ID): sees own personal tasks + member orgs, never Org B
        with rls_context(organization_id=None, user_id=str(owner_a.id), enforced=True):
            user_visible = {str(pk) for pk in Task.objects.values_list("id", flat=True)}
            assert str(personal_task_a.id) in user_visible
            assert str(task_a.id) in user_visible
            assert str(task_b.id) not in user_visible


@pytest.mark.django_db(transaction=True)
def test_postgres_outbox_concurrent_skip_locked_relay_drains_exactly_once() -> None:
    """
    4 concurrent outbox relay workers racing through a Barrier against 6 pending
    OutboxEvent rows on PostgreSQL 16 must dispatch each event strictly once via
    SELECT ... FOR UPDATE SKIP LOCKED with zero duplicate webhook fan-outs.
    """
    owner = User.objects.create_user(email="pg-outbox-owner@example.com", password="pw")
    org = Organization.objects.create(name="PG Outbox Org", slug="pg-outbox-org")
    OrganizationMember.objects.create(user=owner, organization=org, role="owner")
    WebhookEndpoint.objects.create(
        organization=org,
        created_by=owner,
        url="https://sink.example.org/pg-outbox",
        secret="whsec_pg_outbox",
        events=["task.completed"],
    )

    for seq in range(6):
        OutboxEvent.objects.create(
            organization=org,
            topic="webhook",
            event_type="task.completed",
            payload={"seq": seq},
        )

    dispatched_seqs: list[int] = []
    seq_lock = threading.Lock()
    barrier = threading.Barrier(4)

    def _record_delay(_ep_id: str, _ev_type: str, payload: dict[str, int]) -> None:
        with seq_lock:
            dispatched_seqs.append(int(payload["seq"]))

    def _relay_worker(_idx: int) -> dict[str, int]:
        try:
            barrier.wait(timeout=5.0)
            return drain_outbox_batch(batch_size=2)
        finally:
            connections.close_all()

    with patch("apps.tasks.tasks.deliver_webhook_event.delay", side_effect=_record_delay):
        with ThreadPoolExecutor(max_workers=4) as pool:
            worker_results = list(pool.map(_relay_worker, range(4)))

    assert sum(r["dispatched"] for r in worker_results) == 6
    assert sorted(dispatched_seqs) == [0, 1, 2, 3, 4, 5]
    assert OutboxEvent.objects.filter(organization=org, status="dispatched").count() == 6


@pytest.mark.django_db
def test_postgres_pg_trgm_gin_indexes_accelerate_multilingual_ilike_search() -> None:
    """
    Verify on live PostgreSQL 16 that:
    1. Extension pg_trgm and GIN indexes tasks_trans_title_trgm_idx + tasks_trans_desc_trgm_idx exist.
    2. PostgreSQL 16's query planner selects Bitmap Index Scan over both pg_trgm GIN indexes
       for TrigramILike (ILIKE '%...%') predicates on tasks_task_translation.
    3. End-to-end GET /api/v1/tasks/?search=... matches case-insensitive multilingual substrings.
    """
    cache.clear()
    owner = User.objects.create_user(email="pg-trgm@example.com", password="pw")
    org = Organization.objects.create(name="PG Trgm Org", slug="pg-trgm-org")
    OrganizationMember.objects.create(user=owner, organization=org, role="owner")

    target_task = Task.objects.create(user=owner, organization=org, status="pending")
    target_task.set_current_language("fr")
    target_task.title = "Calibration QuantumTrigramProbe francophone"
    target_task.description = "Annotation multilingue haute précision"
    target_task.save()

    other_task = Task.objects.create(user=owner, organization=org, status="pending")
    other_task.set_current_language("en")
    other_task.title = "Unrelated baseline item"
    other_task.description = "Standard review queue"
    other_task.save()

    conn = connections["default"]
    with transaction.atomic():
        with conn.cursor() as cur:
            cur.execute("SELECT extname FROM pg_extension WHERE extname = 'pg_trgm'")
            assert cur.fetchone() == ("pg_trgm",)

            cur.execute("""
                SELECT indexname
                FROM pg_indexes
                WHERE tablename = 'tasks_task_translation'
                  AND indexname IN ('tasks_trans_title_trgm_idx', 'tasks_trans_desc_trgm_idx')
                ORDER BY indexname
                """)
            assert [row[0] for row in cur.fetchall()] == [
                "tasks_trans_desc_trgm_idx",
                "tasks_trans_title_trgm_idx",
            ]

            translation_model = Task._parler_meta.root_model
            trgm_qs = translation_model.objects.filter(language_code__in=["en", "es", "fr"]).filter(
                Q(title__trgm_ilike="QuantumTrigramProbe")
                | Q(description__trgm_ilike="QuantumTrigramProbe")
            )
            sql, params = trgm_qs.query.get_compiler("default").as_sql()
            assert "ILIKE" in sql

            cur.execute("SET LOCAL enable_seqscan = off")
            cur.execute(f"EXPLAIN (FORMAT JSON) {sql}", params)
            plan_json = json.dumps(cur.fetchone()[0])
            assert "tasks_trans_title_trgm_idx" in plan_json
            assert "tasks_trans_desc_trgm_idx" in plan_json

    token = str(RefreshToken.for_user(owner).access_token)
    client = APIClient()
    client.credentials(
        HTTP_AUTHORIZATION=f"Bearer {token}",
        HTTP_X_ORGANIZATION_ID=str(org.id),
    )
    resp = client.get("/api/v1/tasks/?search=trigramprobe")
    assert resp.status_code == 200
    assert resp.json()["count"] == 1
    assert resp.json()["results"][0]["id"] == str(target_task.id)
