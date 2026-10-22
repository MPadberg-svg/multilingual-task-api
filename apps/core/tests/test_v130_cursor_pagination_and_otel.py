"""Tests for v1.3.0: Keyset Cursor Pagination and W3C/OTLP Distributed Tracing."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import override_settings
from django.utils import timezone

import pytest
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.ai_assist.services import AIService
from apps.core.models import AuditLog, Organization, OrganizationMember, WebhookEndpoint
from apps.core.tracing import (
    build_otlp_payload,
    clear_recent_spans,
    get_recent_spans,
    parse_traceparent,
    start_span,
)
from apps.core.webhooks import deliver_webhook_sync
from apps.tasks.models import Task
from config.celery import (
    _finish_celery_worker_span,
    _inject_traceparent_on_publish,
    _start_celery_worker_span,
)

User = get_user_model()


def _jwt_client(user: User) -> APIClient:
    client = APIClient()
    refresh = RefreshToken.for_user(user)
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")
    return client


@pytest.mark.django_db
class TestKeysetCursorPagination:
    """Verify O(1) composite keyset cursor pagination alongside default offset pagination."""

    def setup_method(self) -> None:
        cache.clear()

    def test_cursor_pagination_walks_identical_timestamps_without_duplicates_and_invalidates_cache(
        self,
    ) -> None:
        user = User.objects.create_user(email="cursor@rlhf.ai", password="Password123!")
        org = Organization.objects.create(name="Cursor Org", slug="cursor-org", max_tasks=100)
        OrganizationMember.objects.create(organization=org, user=user, role="owner")

        # Create 5 tasks sharing the exact same created_at timestamp to exercise (-created_at, -id) tie-breaking
        fixed_ts = timezone.now()
        created_ids: set[str] = set()
        for idx in range(5):
            t = Task.objects.create(user=user, organization=org, status="pending")
            t.set_current_language("en")
            t.title = f"Dataset Row {idx}"
            t.save()
            Task.objects.filter(pk=t.pk).update(created_at=fixed_ts)
            created_ids.add(str(t.id))

        client = _jwt_client(user)
        client.credentials(
            HTTP_AUTHORIZATION=client._credentials["HTTP_AUTHORIZATION"],
            HTTP_X_ORGANIZATION_ID=str(org.id),
        )

        # Default mode remains offset pagination
        offset_resp = client.get("/api/v1/tasks/?page_size=2")
        assert offset_resp.status_code == 200
        assert offset_resp["X-Pagination-Mode"] == "offset"
        assert offset_resp.data["count"] == 5

        # Cursor mode walks all 5 rows across 3 pages with zero duplicates or drops
        seen_ids: list[str] = []
        next_url: str | None = "/api/v1/tasks/?pagination=cursor&page_size=2"
        pages = 0
        while next_url:
            resp = client.get(next_url)
            assert resp.status_code == 200
            assert resp["X-Pagination-Mode"] == "cursor"
            assert "count" not in resp.data
            seen_ids.extend(item["id"] for item in resp.data["results"])
            next_url = resp.data["next"]
            pages += 1

        assert pages == 3
        assert len(seen_ids) == 5
        assert set(seen_ids) == created_ids

        # Creating a 6th task invalidates cached cursor pages immediately
        create_resp = client.post("/api/v1/tasks/", {"title": "Newest Row"}, format="json")
        assert create_resp.status_code == 201
        first_cursor_page = client.get("/api/v1/tasks/?pagination=cursor&page_size=2")
        assert first_cursor_page.data["results"][0]["id"] == create_resp.data["id"]

        # Organization audit logs also support cursor pagination
        for i in range(3):
            AuditLog.objects.create(
                organization=org,
                user=user,
                action="updated",
                resource_type="Task",
                resource_id=str(i),
            )
        audit_cursor = client.get(
            f"/api/v1/organizations/{org.id}/audit-logs/?pagination=cursor&page_size=2"
        )
        assert audit_cursor.status_code == 200
        assert audit_cursor["X-Pagination-Mode"] == "cursor"
        assert len(audit_cursor.data["results"]) == 2
        assert audit_cursor.data["next"] is not None


@pytest.mark.django_db
class TestW3CTraceContextAndOTLPExporter:
    """Verify W3C traceparent validation, 4-boundary span correlation, and OTLP/HTTP export."""

    def setup_method(self) -> None:
        cache.clear()
        clear_recent_spans()

    def test_w3c_traceparent_parser_rejects_invalid_and_all_zero_ids(self) -> None:
        assert parse_traceparent(None) is None
        assert parse_traceparent("invalid-header") is None
        assert parse_traceparent("ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01") is None
        assert parse_traceparent(f"00-{'0' * 32}-00f067aa0ba902b7-01") is None
        assert parse_traceparent(f"00-4bf92f3577b34da6a3ce929d0e0e4736-{'0' * 16}-01") is None

        valid = parse_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
        assert valid is not None
        assert valid.trace_id == "4bf92f3577b34da6a3ce929d0e0e4736"
        assert valid.span_id == "00f067aa0ba902b7"
        assert valid.sampled is True

    def test_distributed_trace_propagates_across_http_openai_webhooks_and_celery(self) -> None:
        user = User.objects.create_user(email="otel@rlhf.ai", password="Password123!")
        org = Organization.objects.create(name="OTel Org", slug="otel-org")
        OrganizationMember.objects.create(organization=org, user=user, role="owner")
        endpoint = WebhookEndpoint.objects.create(
            organization=org,
            created_by=user,
            url="https://collector.partner.example/webhook",
            secret="whsec_0123456789abcdef0123456789abcdef",
            events=["task.completed"],
        )

        incoming_trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"
        incoming_span_id = "00f067aa0ba902b7"
        incoming_tp = f"00-{incoming_trace_id}-{incoming_span_id}-01"

        # 1. HTTP request preserves incoming trace_id and returns traceparent + X-Trace-ID
        client = _jwt_client(user)
        resp = client.get("/api/v1/auth/me/", HTTP_TRACEPARENT=incoming_tp)
        assert resp.status_code == 200
        assert resp["X-Trace-ID"] == incoming_trace_id
        assert resp["traceparent"].startswith(f"00-{incoming_trace_id}-")

        # 2. Parent span -> OpenAI child span + Celery header injection + Webhook traceparent
        fake_completion = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content=json.dumps(
                            {
                                "en": {"title": "Hello", "description": "World"},
                                "es": {"title": "Hola", "description": "Mundo"},
                                "fr": {"title": "Bonjour", "description": "Monde"},
                            }
                        )
                    )
                )
            ],
            usage=SimpleNamespace(prompt_tokens=120, completion_tokens=80),
        )
        ai_svc = AIService()
        mock_openai = MagicMock()
        mock_openai.chat.completions.create.return_value = fake_completion
        ai_svc._client = mock_openai

        captured_webhook_headers: dict[str, str] = {}

        def _capture_wh(safe_url: str, body: bytes, headers: dict[str, str]) -> int:
            captured_webhook_headers.update(headers)
            return 200

        celery_headers: dict[str, str] = {}
        with start_span("parent.workflow", parent_traceparent=incoming_tp) as root_span:
            ai_svc.suggest_task_translations(
                user_id=str(user.id),
                lang="en",
                user_input="Trace OpenAI span",
                organization_id=str(org.id),
            )
            _inject_traceparent_on_publish(headers=celery_headers)

            with (
                patch(
                    "apps.core.webhooks.socket.getaddrinfo",
                    return_value=[(2, 1, 6, "", ("93.184.216.34", 443))],
                ),
                patch("apps.core.webhooks._send_http_post_no_redirect", side_effect=_capture_wh),
            ):
                deliver_webhook_sync(endpoint, "task.completed", {"task_id": "t-otel"})

        # Outbound webhook received propagated W3C traceparent sharing incoming_trace_id
        assert captured_webhook_headers["traceparent"].startswith(f"00-{incoming_trace_id}-")
        assert celery_headers["traceparent"] == root_span.traceparent

        # Simulate Celery worker consuming those headers via task_prerun / task_postrun
        fake_celery_task = SimpleNamespace(
            name="apps.tasks.tasks.generate_task_translations",
            request=SimpleNamespace(headers=celery_headers, traceparent=None),
        )
        _start_celery_worker_span(task_id="celery-123", task=fake_celery_task)
        _finish_celery_worker_span(task_id="celery-123", state="SUCCESS")

        spans = get_recent_spans()
        by_name = {s.name: s for s in spans}
        assert by_name["GET /api/v1/auth/me/"].parent_span_id == incoming_span_id
        assert by_name["openai.chat.completions"].trace_id == incoming_trace_id
        assert by_name["openai.chat.completions"].attributes["gen_ai.usage.input_tokens"] == 120
        assert by_name["webhook.deliver"].trace_id == incoming_trace_id
        assert (
            by_name["celery.task:apps.tasks.tasks.generate_task_translations"].trace_id
            == incoming_trace_id
        )

    @override_settings(
        OTEL_EXPORTER_OTLP_ENDPOINT="https://otel.collector.example/v1/traces",
        OTEL_EXPORTER_OTLP_HEADERS="Authorization=Bearer otel-secret,X-Env=prod",
    )
    def test_otlp_http_json_exporter_formats_and_dispatches_cleanly(self) -> None:
        fake_resp = MagicMock(status=200)
        fake_conn = MagicMock()
        fake_conn.getresponse.return_value = fake_resp

        with patch("apps.core.tracing.http.client.HTTPSConnection", return_value=fake_conn):
            with start_span(
                "custom.operation",
                attributes={"flag": True, "count": 7, "ratio": 0.95, "label": "ok"},
            ) as sp:
                otlp = build_otlp_payload(sp)

        assert fake_conn.request.called
        req_args, req_kwargs = fake_conn.request.call_args
        assert req_args[0] == "POST"
        assert req_args[1] == "/v1/traces"
        assert req_kwargs["headers"]["Authorization"] == "Bearer otel-secret"
        assert otlp["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["name"] == "custom.operation"

        # Collector network failure must never raise into application code
        with patch(
            "apps.core.tracing.http.client.HTTPSConnection",
            side_effect=OSError("collector unreachable"),
        ):
            with start_span("resilient.span"):
                pass
