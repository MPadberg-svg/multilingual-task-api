"""Live PostgreSQL 16 & Redis 7 integration tests.

Exercises real ``SELECT ... FOR UPDATE SKIP LOCKED LIMIT 1`` multi-connection
concurrency, ``django-redis`` ``ZlibCompressor`` + ``INCRBY`` wire operations,
Redis Pub/Sub ``EventPublisher`` delivery, and ``channels-redis`` WebSockets.
"""

from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db import connections, transaction

import pytest
from asgiref.sync import sync_to_async
from channels.layers import get_channel_layer
from channels.testing import WebsocketCommunicator
from django_redis import get_redis_connection
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

from apps.core.events import EventPublisher, broadcast_task_websocket_event
from apps.core.models import Organization, OrganizationMember
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
    org = Organization.objects.create(name="PG Stampede Org", slug="pg-stampede-org")
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
