"""Tests for Wave 4 & Wave 3 FinOps: M2M API Keys, SSRF-Safe HMAC Webhooks, AI FinOps Telemetry, and /explorer/ CSP."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import timedelta
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
from apps.core.models import Organization, OrganizationAPIKey, OrganizationMember, WebhookEndpoint
from apps.core.webhooks import (
    _send_http_post_no_redirect,
    deliver_webhook_sync,
    dispatch_organization_webhooks,
    validate_webhook_url,
)
from apps.tasks.tasks import deliver_webhook_event

User = get_user_model()


def _jwt_client(user: User) -> APIClient:
    client = APIClient()
    refresh = RefreshToken.for_user(user)
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")
    return client


@pytest.mark.django_db
class TestScopedOrganizationAPIKeys:
    """Verify SHA-256 M2M API key creation, scope enforcement, expiration, and revocation."""

    def setup_method(self) -> None:
        cache.clear()

    def test_api_key_lifecycle_scopes_tenant_binding_and_revocation(self) -> None:
        owner = User.objects.create_user(email="key-owner@org.io", password="Password123!")
        org = Organization.objects.create(name="Key Org", slug="key-org", max_tasks=50)
        other_org = Organization.objects.create(name="Other Org", slug="other-org", max_tasks=50)
        OrganizationMember.objects.create(organization=org, user=owner, role="owner")
        OrganizationMember.objects.create(organization=other_org, user=owner, role="owner")

        jwt_c = _jwt_client(owner)

        # Create a read-only API key (only tasks:read scope)
        mint_read = jwt_c.post(
            f"/api/v1/organizations/{org.id}/api-keys/",
            {"name": "CI Reader", "role": "viewer", "scopes": ["tasks:read"]},
            format="json",
        )
        assert mint_read.status_code == 201
        raw_read_key = mint_read.data["api_key"]
        read_key_id = mint_read.data["id"]
        assert raw_read_key.startswith("mlk_live_")

        # Listing keys never exposes raw api_key or hashed_key
        list_resp = jwt_c.get(f"/api/v1/organizations/{org.id}/api-keys/")
        assert list_resp.status_code == 200
        assert "api_key" not in list_resp.data[0]
        assert "hashed_key" not in list_resp.data[0]

        read_client = APIClient()
        read_client.credentials(HTTP_X_API_KEY=raw_read_key)

        # GET /api/v1/tasks/ succeeds with tasks:read scope
        assert read_client.get("/api/v1/tasks/").status_code == 200

        # POST /api/v1/tasks/ fails with 403 (missing tasks:write scope)
        assert (
            read_client.post("/api/v1/tasks/", {"title": "Blocked"}, format="json").status_code
            == 403
        )

        # GET /api/v1/tasks/export/ fails with 403 (missing tasks:export scope)
        assert read_client.get("/api/v1/tasks/export/?format=jsonl").status_code == 403

        # Passing mismatched X-Organization-ID header with API key fails with 403
        mismatch_client = APIClient()
        mismatch_client.credentials(
            HTTP_X_API_KEY=raw_read_key,
            HTTP_X_ORGANIZATION_ID=str(other_org.id),
        )
        assert mismatch_client.get("/api/v1/tasks/").status_code == 403

        # Mint write-capable key using Authorization: Api-Key header
        mint_write = jwt_c.post(
            f"/api/v1/organizations/{org.id}/api-keys/",
            {"name": "Ingest Bot", "role": "contributor", "scopes": ["tasks:read", "tasks:write"]},
            format="json",
        )
        raw_write_key = mint_write.data["api_key"]
        write_client = APIClient()
        write_client.credentials(HTTP_AUTHORIZATION=f"Api-Key {raw_write_key}")
        created = write_client.post(
            "/api/v1/tasks/", {"title": "Created via M2M key"}, format="json"
        )
        assert created.status_code == 201
        assert created.data["organization"] == str(org.id)

        # Revoking read key immediately invalidates authentication (401)
        revoke_resp = jwt_c.delete(f"/api/v1/organizations/{org.id}/api-keys/{read_key_id}/")
        assert revoke_resp.status_code == 204
        assert read_client.get("/api/v1/tasks/").status_code == 401

        # Expired key is rejected with 401
        OrganizationAPIKey.objects.filter(id=mint_write.data["id"]).update(
            expires_at=timezone.now() - timedelta(seconds=10)
        )
        assert write_client.get("/api/v1/tasks/").status_code == 401


@pytest.mark.django_db
class TestSSRFHardenedWebhooksAndHMACSigning:
    """Verify SSRF IP/DNS blocking, HMAC-SHA256 signing, failure auto-disable, and Celery retry."""

    @override_settings(DEBUG=False)
    def test_ssrf_blocks_http_localhost_metadata_and_dns_rebinding(self) -> None:
        with pytest.raises(ValueError, match="https"):
            validate_webhook_url("http://hooks.example.com/webhook")

        for forbidden_url in [
            "https://localhost/hook",
            "https://127.0.0.1/hook",
            "https://169.254.169.254/latest/meta-data/",
            "https://10.0.0.5/internal",
            "https://service.internal/hook",
        ]:
            with pytest.raises(ValueError):
                validate_webhook_url(forbidden_url)

        # Simulate DNS rebinding where public-looking domain resolves to private IP 192.168.1.25
        with patch(
            "apps.core.webhooks.socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("192.168.1.25", 443))],
        ):
            with pytest.raises(ValueError, match="forbidden private or metadata IP"):
                validate_webhook_url("https://rebind.attacker.example/hook", resolve_dns=True)

    def test_webhook_registration_hmac_signature_and_failure_circuit_breaker(self) -> None:
        owner = User.objects.create_user(email="wh@org.io", password="Password123!")
        org = Organization.objects.create(name="Hook Org", slug="hook-org")
        OrganizationMember.objects.create(organization=org, user=owner, role="owner")
        client = _jwt_client(owner)

        # SSRF registration attempt via API returns 400
        bad_reg = client.post(
            f"/api/v1/organizations/{org.id}/webhooks/",
            {"url": "https://169.254.169.254/latest/meta-data/", "events": ["task.completed"]},
            format="json",
        )
        assert bad_reg.status_code == 400

        reg = client.post(
            f"/api/v1/organizations/{org.id}/webhooks/",
            {
                "url": "https://hooks.partner.example/rlhf",
                "description": "Partner sink",
                "events": ["task.completed", "task.consensus_reached"],
            },
            format="json",
        )
        assert reg.status_code == 201
        wh_id = reg.data["id"]
        signing_secret = reg.data["signing_secret"]
        assert signing_secret.startswith("whsec_")

        captured: dict[str, object] = {}

        def _fake_post(safe_url: str, body_bytes: bytes, headers: dict[str, str]) -> int:
            captured["url"] = safe_url
            captured["body"] = body_bytes
            captured["headers"] = headers
            return 200

        with (
            patch(
                "apps.core.webhooks.socket.getaddrinfo",
                return_value=[(2, 1, 6, "", ("93.184.216.34", 443))],
            ),
            patch("apps.core.webhooks._send_http_post_no_redirect", side_effect=_fake_post),
        ):
            ping_resp = client.post(f"/api/v1/organizations/{org.id}/webhooks/{wh_id}/test/")
            assert ping_resp.status_code == 200
            assert ping_resp.data["success"] is True

        sent_headers = captured["headers"]
        assert isinstance(sent_headers, dict)
        sent_body = captured["body"]
        assert isinstance(sent_body, bytes)
        ts = sent_headers["X-MLTask-Timestamp"]
        expected_sig = (
            "sha256="
            + hmac.new(
                signing_secret.encode("utf-8"),
                f"{ts}.".encode("utf-8") + sent_body,
                hashlib.sha256,
            ).hexdigest()
        )
        assert sent_headers["X-MLTask-Signature-256"] == expected_sig

        # Verify endpoint auto-disables after 10 consecutive failures
        ep = WebhookEndpoint.objects.get(id=wh_id)
        ep.failure_count = 9
        ep.save(update_fields=["failure_count"])
        with (
            patch(
                "apps.core.webhooks.socket.getaddrinfo",
                return_value=[(2, 1, 6, "", ("93.184.216.34", 443))],
            ),
            patch("apps.core.webhooks._send_http_post_no_redirect", return_value=500),
        ):
            failed_delivery = deliver_webhook_sync(ep, "task.completed", {"task_id": "123"})
            assert failed_delivery.success is False
            ep.refresh_from_db()
            assert ep.failure_count == 10
            assert ep.is_active is False

        # Re-enable and verify Celery task deliver_webhook_event succeeds on 202
        ep.is_active = True
        ep.failure_count = 0
        ep.save(update_fields=["is_active", "failure_count"])
        with (
            patch(
                "apps.core.webhooks.socket.getaddrinfo",
                return_value=[(2, 1, 6, "", ("93.184.216.34", 443))],
            ),
            patch("apps.core.webhooks._send_http_post_no_redirect", return_value=202),
        ):
            celery_res = deliver_webhook_event(str(ep.id), "task.completed", {"task_id": "abc"})
            assert celery_res["delivered"] is True


@pytest.mark.django_db
class TestAIFinOpsTelemetryAndExplorerConsoleCSP:
    """Verify OpenAI token/USD FinOps accounting and strict nonce CSP on /explorer/."""

    def setup_method(self) -> None:
        cache.clear()

    def test_openai_token_usage_surfaces_in_org_usage_and_prometheus_metrics(self) -> None:
        owner = User.objects.create_user(email="finops@org.io", password="Password123!")
        org = Organization.objects.create(name="FinOps Org", slug="finops-org")
        OrganizationMember.objects.create(organization=org, user=owner, role="owner")

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
            usage=SimpleNamespace(prompt_tokens=1000, completion_tokens=500),
        )
        service = AIService()
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = fake_completion
        service._client = mock_client

        service.suggest_task_translations(
            user_id=str(owner.id),
            lang="en",
            user_input="Translate greeting",
            organization_id=str(org.id),
        )

        client = _jwt_client(owner)
        usage_resp = client.get(f"/api/v1/organizations/{org.id}/usage/")
        assert usage_resp.status_code == 200
        ai_tel = usage_resp.data["ai_telemetry"]
        assert ai_tel["requests_total"] == 1
        assert ai_tel["prompt_tokens_total"] == 1000
        assert ai_tel["completion_tokens_total"] == 500
        assert ai_tel["estimated_cost_usd"] == pytest.approx(0.00045, rel=1e-4)

        with override_settings(METRICS_TOKEN="secret-prom-token"):
            prom_resp = APIClient().get(
                "/api/v1/metrics/", HTTP_AUTHORIZATION="Bearer secret-prom-token"
            )
            assert prom_resp.status_code == 200
            body = prom_resp.content.decode("utf-8")
            assert "mltask_ai_prompt_tokens_total 1000" in body
            assert "mltask_ai_completion_tokens_total 500" in body
            assert "mltask_ai_estimated_cost_usd_total 0.000450" in body

    def test_explorer_console_uses_cryptographic_csp_nonce_without_unsafe_inline(self) -> None:
        resp = APIClient().get("/explorer/")
        assert resp.status_code == 200
        csp = resp["Content-Security-Policy"]
        assert "'unsafe-inline'" not in csp
        assert "'nonce-" in csp
        assert "connect-src 'self' ws: wss:;" in csp

        html = resp.content.decode("utf-8")
        assert 'style="' not in html
        assert "onclick=" not in html
        # Nonce in CSP header matches rendered <style nonce="..."> and <script nonce="...">
        nonce = csp.split("'nonce-")[1].split("'")[0]
        assert f'<style nonce="{nonce}">' in html
        assert f'<script nonce="{nonce}">' in html

    def test_http_no_redirect_transport_webhook_fanout_and_org_detail_endpoints(self) -> None:
        owner = User.objects.create_user(email="ops-extra@org.io", password="Password123!")
        client = _jwt_client(owner)

        # Create org, list orgs, get/patch org detail, list members
        org_resp = client.post(
            "/api/v1/organizations/", {"name": "Ops Org", "slug": "ops-org"}, format="json"
        )
        org_id = org_resp.data["id"]
        assert client.get("/api/v1/organizations/").status_code == 200
        assert client.get(f"/api/v1/organizations/{org_id}/").status_code == 200
        assert (
            client.patch(
                f"/api/v1/organizations/{org_id}/", {"name": "Ops Org Updated"}, format="json"
            ).status_code
            == 200
        )
        assert client.get(f"/api/v1/organizations/{org_id}/members/").status_code == 200

        # Invalid refresh token on logout returns 400
        assert (
            client.post("/api/v1/auth/logout/", {"refresh": "not-a-jwt"}, format="json").status_code
            == 400
        )

        # Claiming when queue is empty returns 204 No Content
        assert client.post("/api/v1/tasks/claim/", {}, format="json").status_code == 204

        # Register, list, fanout, and delete webhook endpoint
        wh_resp = client.post(
            f"/api/v1/organizations/{org_id}/webhooks/",
            {"url": "https://sink.example.org/events?env=prod", "events": ["task.created"]},
            format="json",
        )
        wh_id = wh_resp.data["id"]
        assert client.get(f"/api/v1/organizations/{org_id}/webhooks/").status_code == 200

        with patch("apps.tasks.tasks.deliver_webhook_event.delay") as mock_delay:
            dispatched = dispatch_organization_webhooks(org_id, "task.created", {"task_id": "t1"})
            assert dispatched == 1
            mock_delay.assert_called_once()

        # Exercise _send_http_post_no_redirect HTTPS & HTTP branches with mocked http.client
        fake_resp = MagicMock(status=204)
        fake_conn = MagicMock()
        fake_conn.getresponse.return_value = fake_resp
        with patch("apps.core.webhooks.http.client.HTTPSConnection", return_value=fake_conn):
            code = _send_http_post_no_redirect(
                "https://sink.example.org/events?env=prod",
                b"{}",
                {"Content-Type": "application/json"},
            )
            assert code == 204
            fake_conn.close.assert_called_once()

        fake_http_conn = MagicMock()
        fake_http_conn.getresponse.return_value = fake_resp
        with patch("apps.core.webhooks.http.client.HTTPConnection", return_value=fake_http_conn):
            code_http = _send_http_post_no_redirect(
                "http://sink.example.org/events", b"{}", {"Content-Type": "application/json"}
            )
            assert code_http == 204

        assert client.delete(f"/api/v1/organizations/{org_id}/webhooks/{wh_id}/").status_code == 204
