"""Security and integration tests for HTTP /graphql/ (JWT + IDOR + RBAC) and WebSockets."""

from __future__ import annotations

import json

from django.contrib.auth import get_user_model
from django.test import AsyncClient

import pytest
from channels.db import database_sync_to_async
from channels.testing import WebsocketCommunicator
from rest_framework_simplejwt.tokens import RefreshToken

from apps.core.models import Organization, OrganizationMember
from apps.tasks.models import Task
from config.asgi import application

User = get_user_model()


@pytest.mark.django_db(transaction=True)
class TestGraphQLHTTPAndIDORSecurity:
    """Verify real HTTP /graphql/ execution with StrawberryDjangoContext, JWT, RBAC, and IDOR checks."""

    @pytest.mark.asyncio
    async def test_http_graphql_jwt_create_query_and_idor_protection(self):
        alice = await database_sync_to_async(User.objects.create_user)(
            email="alice_gql@example.com", password="pw"
        )
        mallory = await database_sync_to_async(User.objects.create_user)(
            email="mallory_gql@example.com", password="pw"
        )
        org = await database_sync_to_async(Organization.objects.create)(
            name="GraphQL Org", slug="graphql-org", max_tasks=2
        )
        await database_sync_to_async(OrganizationMember.objects.create)(
            organization=org, user=alice, role="owner"
        )

        alice_token = str((await database_sync_to_async(RefreshToken.for_user)(alice)).access_token)
        mallory_token = str(
            (await database_sync_to_async(RefreshToken.for_user)(mallory)).access_token
        )

        client = AsyncClient()

        # 1. Alice creates a task via real HTTP POST /graphql/ using JWT Bearer header
        create_mutation = """
        mutation($title: String!, $desc: String!) {
          createTask(title: $title, description: $desc) {
            id
            title
            description
            status
            translations {
              languageCode
              title
              description
            }
            createdAt
          }
        }
        """
        resp_create = await client.post(
            "/graphql/",
            data=json.dumps(
                {
                    "query": create_mutation,
                    "variables": {
                        "title": "GraphQL Secure Task",
                        "desc": "Created over HTTP",
                    },
                }
            ),
            content_type="application/json",
            headers={
                "Authorization": f"Bearer {alice_token}",
                "X-Organization-ID": str(org.id),
            },
        )
        assert resp_create.status_code == 200
        body = resp_create.json()
        assert "errors" not in body, body
        assert body["data"]["createTask"] is not None
        task_id = body["data"]["createTask"]["id"]
        assert body["data"]["createTask"]["title"] == "GraphQL Secure Task"
        assert body["data"]["createTask"]["translations"][0]["languageCode"] == "en"

        # 2. Alice queries tasks, task(id), organizations, and organization(id) over HTTP /graphql/
        query_doc = """
        query($orgId: UUID!, $taskId: UUID!) {
          tasks(organizationId: $orgId) {
            id
            title
            description
            status
          }
          task(id: $taskId) {
            id
            title
          }
          organizations {
            id
            name
            taskCount
            memberCount
          }
          organization(id: $orgId) {
            id
            name
            plan
            taskCount
            memberCount
          }
        }
        """
        resp_query = await client.post(
            "/graphql/",
            data=json.dumps(
                {"query": query_doc, "variables": {"orgId": str(org.id), "taskId": task_id}}
            ),
            content_type="application/json",
            headers={"Authorization": f"Bearer {alice_token}"},
        )
        q_body = resp_query.json()
        assert "errors" not in q_body, q_body
        assert len(q_body["data"]["tasks"]) == 1
        assert q_body["data"]["task"]["title"] == "GraphQL Secure Task"
        assert q_body["data"]["organization"]["memberCount"] == 1
        assert q_body["data"]["organization"]["taskCount"] == 1

        # 3. Mallory (non-member) CANNOT view Alice's organization/task or mutate Alice's task (IDOR blocked!)
        resp_org_idor = await client.post(
            "/graphql/",
            data=json.dumps(
                {"query": query_doc, "variables": {"orgId": str(org.id), "taskId": task_id}}
            ),
            content_type="application/json",
            headers={"Authorization": f"Bearer {mallory_token}"},
        )
        idor_data = resp_org_idor.json()["data"]
        assert idor_data["organization"] is None
        assert idor_data["task"] is None
        assert idor_data["tasks"] == []

        update_mutation = """
        mutation($id: UUID!, $status: String!) {
          updateTaskStatus(taskId: $id, newStatus: $status) {
            id
            status
          }
        }
        """
        resp_update_idor = await client.post(
            "/graphql/",
            data=json.dumps(
                {
                    "query": update_mutation,
                    "variables": {"id": task_id, "status": "completed"},
                }
            ),
            content_type="application/json",
            headers={"Authorization": f"Bearer {mallory_token}"},
        )
        assert resp_update_idor.json()["data"]["updateTaskStatus"] is None

        # Verify task status in DB was NOT modified by Mallory
        alice_task = await database_sync_to_async(Task.objects.get)(id=task_id)
        assert alice_task.status == "pending"

        # 4. Alice CAN legitimately update her task's status
        resp_update_ok = await client.post(
            "/graphql/",
            data=json.dumps(
                {
                    "query": update_mutation,
                    "variables": {"id": task_id, "status": "completed"},
                }
            ),
            content_type="application/json",
            headers={"Authorization": f"Bearer {alice_token}"},
        )
        assert resp_update_ok.json()["data"]["updateTaskStatus"]["status"] == "completed"


@pytest.mark.django_db(transaction=True)
class TestWebSocketTenantIsolationAndBroadcast:
    """Verify WebSocket Bearer auth, org membership, subscribe_task ACL, and real-time events."""

    @pytest.mark.asyncio
    async def test_ws_rejects_non_member_org_with_4003_and_allows_member_via_bearer_header(self):
        member = await database_sync_to_async(User.objects.create_user)(
            email="wsmember@example.com", password="pw"
        )
        outsider = await database_sync_to_async(User.objects.create_user)(
            email="wsoutsider@example.com", password="pw"
        )
        org = await database_sync_to_async(Organization.objects.create)(
            name="WS Org", slug="ws-org"
        )
        await database_sync_to_async(OrganizationMember.objects.create)(
            organization=org, user=member, role="contributor"
        )

        outsider_token = str(
            (await database_sync_to_async(RefreshToken.for_user)(outsider)).access_token
        )
        member_token = str(
            (await database_sync_to_async(RefreshToken.for_user)(member)).access_token
        )

        # Outsider attempting to join /ws/tasks/{org.id}/ must be rejected with 4003
        comm_bad = WebsocketCommunicator(
            application,
            f"/ws/tasks/{org.id}/",
            headers=[(b"authorization", f"Bearer {outsider_token}".encode())],
        )
        connected_bad, code_bad = await comm_bad.connect()
        assert connected_bad is False
        assert code_bad == 4003

        # Member connecting with Authorization: Bearer header succeeds and receives live org broadcasts
        comm_ok = WebsocketCommunicator(
            application,
            f"/ws/tasks/{org.id}/",
            headers=[(b"authorization", f"Bearer {member_token}".encode())],
        )
        connected_ok, _ = await comm_ok.connect()
        assert connected_ok is True
        welcome = await comm_ok.receive_json_from()
        assert welcome["type"] == "connection_established"
        assert welcome["organization_id"] == str(org.id)

        # Ping / Pong & invalid JSON error resilience
        await comm_ok.send_json_to({"type": "ping"})
        pong = await comm_ok.receive_json_from()
        assert pong == {"type": "pong"}

        await comm_ok.send_to(text_data="not-json")
        err_msg = await comm_ok.receive_json_from()
        assert err_msg["type"] == "error"

        await comm_ok.send_json_to({"type": "unknown_action"})
        err_unknown = await comm_ok.receive_json_from()
        assert err_unknown["type"] == "error"

        # Creating & soft-deleting an org task triggers signal -> EventPublisher -> Channels WS frame!
        org_task = await database_sync_to_async(Task.objects.create)(
            user=member, organization=org, status="in_progress"
        )
        live_created = await comm_ok.receive_json_from()
        assert live_created["type"] == "task_update"
        assert live_created["data"]["id"] == str(org_task.id)

        await database_sync_to_async(org_task.delete)()
        live_deleted = await comm_ok.receive_json_from()
        assert live_deleted["type"] == "task_deleted"
        assert live_deleted["data"]["id"] == str(org_task.id)

        await comm_ok.disconnect()

    @pytest.mark.asyncio
    async def test_ws_subscribe_task_blocks_unauthorized_and_validates_uuid(self):
        owner = await database_sync_to_async(User.objects.create_user)(
            email="wsowner@example.com", password="pw"
        )
        intruder = await database_sync_to_async(User.objects.create_user)(
            email="wsintruder@example.com", password="pw"
        )
        private_task = await database_sync_to_async(Task.objects.create)(
            user=owner, status="pending"
        )
        intruder_token = str(
            (await database_sync_to_async(RefreshToken.for_user)(intruder)).access_token
        )
        owner_token = str((await database_sync_to_async(RefreshToken.for_user)(owner)).access_token)

        # Intruder cannot subscribe to owner's private task
        comm_intruder = WebsocketCommunicator(application, f"/ws/tasks/?token={intruder_token}")
        connected, _ = await comm_intruder.connect()
        assert connected is True
        await comm_intruder.receive_json_from()  # consume connection_established

        await comm_intruder.send_json_to({"type": "subscribe_task", "task_id": "bad-uuid"})
        r_uuid = await comm_intruder.receive_json_from()
        assert r_uuid["type"] == "error"

        await comm_intruder.send_json_to(
            {"type": "subscribe_task", "task_id": str(private_task.id)}
        )
        r_denied = await comm_intruder.receive_json_from()
        assert r_denied["type"] == "error"
        await comm_intruder.disconnect()

        # Owner CAN subscribe and unsubscribe cleanly
        comm_owner = WebsocketCommunicator(application, f"/ws/tasks/?token={owner_token}")
        await comm_owner.connect()
        await comm_owner.receive_json_from()  # consume connection_established

        await comm_owner.send_json_to({"type": "subscribe_task", "task_id": str(private_task.id)})
        r_sub = await comm_owner.receive_json_from()
        assert r_sub == {"type": "subscribed", "task_id": str(private_task.id)}

        await comm_owner.send_json_to({"type": "unsubscribe_task", "task_id": str(private_task.id)})
        r_unsub = await comm_owner.receive_json_from()
        assert r_unsub == {"type": "unsubscribed", "task_id": str(private_task.id)}

        await comm_owner.disconnect()
