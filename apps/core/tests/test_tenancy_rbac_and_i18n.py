"""Comprehensive tests for RFC 9110 i18n, JWT multi-tenancy, 4-tier RBAC, quotas, and commands."""

from __future__ import annotations

import uuid
from io import StringIO
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.test import RequestFactory

import pytest
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.core.middleware import resolve_language_from_request
from apps.core.models import Organization, OrganizationMember
from apps.core.security import InputValidator
from apps.tasks.models import Task

User = get_user_model()


class TestRFC9110AcceptLanguage:
    """Verify quality-weighted Accept-Language negotiation."""

    def test_parses_quality_weights_highest_supported_wins(self):
        rf = RequestFactory()
        req = rf.get(
            "/api/v1/tasks/",
            HTTP_ACCEPT_LANGUAGE="de-DE;q=0.9, es-MX;q=0.7, fr-CA;q=0.85, en;q=0.5",
        )
        assert resolve_language_from_request(req) == "fr"

    def test_ignores_zero_quality_and_malformed_weights(self):
        rf = RequestFactory()
        req = rf.get("/api/v1/tasks/", HTTP_ACCEPT_LANGUAGE="fr;q=0, es;q=bad, en-US;q=0.6")
        assert resolve_language_from_request(req) == "en"

    def test_empty_or_unmatched_header_returns_default_en(self):
        rf = RequestFactory()
        assert resolve_language_from_request(rf.get("/api/v1/tasks/")) == "en"
        assert (
            resolve_language_from_request(
                rf.get("/api/v1/tasks/", HTTP_ACCEPT_LANGUAGE="ja-JP, zh-CN;q=0.9")
            )
            == "en"
        )

    @pytest.mark.django_db
    def test_end_to_end_weighted_header_selects_spanish(self):
        user = User.objects.create_user(email="lang@example.com", password="password123")
        task = Task.objects.create(user=user, status="pending")
        task.set_current_language("en")
        task.title = "English Title"
        task.save()
        task.set_current_language("es")
        task.title = "Título en Español"
        task.save()

        client = APIClient()
        token = str(RefreshToken.for_user(user).access_token)
        resp = client.get(
            f"/api/v1/tasks/{task.id}/",
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_ACCEPT_LANGUAGE="pt-BR;q=0.95, es-ES;q=0.8, en;q=0.4",
        )
        assert resp.status_code == 200
        assert resp.json()["title"] == "Título en Español"
        assert resp.json()["language"] == "es"


class TestInputValidatorUTF8AndSecurity:
    """Verify UTF-8 preservation alongside XSS/SQLi/code-injection defense."""

    def test_preserves_multilingual_accents_cjk_and_emoji(self):
        raw = "Evaluación de calidad — tâche n°1 日本語 🚀"
        sanitized = InputValidator.sanitize_string(raw)
        assert sanitized == raw

    def test_strips_control_bytes_and_enforces_length(self):
        raw = "Bonjour\x00 le monde"
        sanitized = InputValidator.sanitize_string(raw)
        assert "\x00" not in sanitized
        assert sanitized == "Bonjour le monde"

        with pytest.raises(ValueError, match="exceeds maximum length"):
            InputValidator.sanitize_string("x" * 25, max_length=10)
        with pytest.raises(ValueError, match="exceeds maximum length"):
            InputValidator.sanitize_html("x" * 25, max_length=10)

    def test_full_sanitize_blocks_sqli_and_xss(self):
        with pytest.raises(ValueError, match="Security violation"):
            InputValidator.full_sanitize("<script>alert(1)</script>")
        with pytest.raises(ValueError, match="Security violation"):
            InputValidator.full_sanitize("1 UNION SELECT password FROM users")
        assert InputValidator.full_sanitize("Safe <b>bold</b>") == "Safe &lt;b&gt;bold&lt;/b&gt;"

    def test_validate_code_input_blocks_dangerous_imports_and_allows_safe_code(self):
        safe_code = "def add(a: int, b: int) -> int:\n    return a + b\n"
        assert InputValidator.validate_code_input(safe_code) == (False, "")

        blocked, reason = InputValidator.validate_code_input(
            "import subprocess\nsubprocess.Popen(['ls'])"
        )
        assert blocked is True
        assert "subprocess" in reason


@pytest.mark.django_db
class TestMultiTenancyRBACAndQuotas:
    """Verify JWT TenantMiddleware, 4-tier RBAC, max_tasks, and max_users enforcement."""

    def _jwt_client(self, user) -> tuple[APIClient, str]:
        client = APIClient()
        token = str(RefreshToken.for_user(user).access_token)
        return client, token

    def test_organization_seat_quota_enforced_on_member_creation(self):
        org = Organization.objects.create(name="Small Org", slug="small-org", max_users=2)
        u1 = User.objects.create_user(email="u1@example.com", password="pw")
        u2 = User.objects.create_user(email="u2@example.com", password="pw")
        u3 = User.objects.create_user(email="u3@example.com", password="pw")

        OrganizationMember.objects.create(organization=org, user=u1, role="owner")
        OrganizationMember.objects.create(organization=org, user=u2, role="viewer")

        with pytest.raises(ValidationError, match="seat limit exceeded"):
            OrganizationMember.objects.create(organization=org, user=u3, role="viewer")

        # Updating an existing member's role must still succeed at capacity
        existing = OrganizationMember.objects.get(organization=org, user=u2)
        existing.role = "contributor"
        existing.save()
        assert existing.role == "contributor"

    def test_jwt_tenant_middleware_blocks_non_member_and_invalid_uuid(self):
        org = Organization.objects.create(name="Alpha", slug="alpha")
        outsider = User.objects.create_user(email="outsider@example.com", password="pw")
        client, token = self._jwt_client(outsider)

        bad_uuid_resp = client.get(
            "/api/v1/tasks/",
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_X_ORGANIZATION_ID="not-a-valid-uuid",
        )
        assert bad_uuid_resp.status_code == 400

        non_member_resp = client.get(
            "/api/v1/tasks/",
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_X_ORGANIZATION_ID=str(org.id),
        )
        assert non_member_resp.status_code == 403

        missing_org_resp = client.get(
            "/api/v1/tasks/",
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_X_ORGANIZATION_ID=str(uuid.uuid4()),
        )
        assert missing_org_resp.status_code == 403

    def test_four_tier_rbac_viewer_contributor_and_admin(self):
        org = Organization.objects.create(name="RBAC Org", slug="rbac-org")
        owner = User.objects.create_user(email="owner@example.com", password="pw")
        contributor = User.objects.create_user(email="contrib@example.com", password="pw")
        viewer = User.objects.create_user(email="viewer@example.com", password="pw")

        OrganizationMember.objects.create(organization=org, user=owner, role="owner")
        OrganizationMember.objects.create(organization=org, user=contributor, role="contributor")
        OrganizationMember.objects.create(organization=org, user=viewer, role="viewer")

        # Contributor can create and read org tasks
        c_client, c_token = self._jwt_client(contributor)
        create_resp = c_client.post(
            "/api/v1/tasks/",
            {"title": "Shared Org Task", "description": "Created by contributor"},
            format="json",
            HTTP_AUTHORIZATION=f"Bearer {c_token}",
            HTTP_X_ORGANIZATION_ID=str(org.id),
        )
        assert create_resp.status_code == 201
        task_id = create_resp.json()["id"]

        # Viewer can GET org tasks, but cannot POST, PATCH, or DELETE
        v_client, v_token = self._jwt_client(viewer)
        get_resp = v_client.get(
            "/api/v1/tasks/",
            HTTP_AUTHORIZATION=f"Bearer {v_token}",
            HTTP_X_ORGANIZATION_ID=str(org.id),
        )
        assert get_resp.status_code == 200
        assert get_resp.json()["count"] == 1

        viewer_post = v_client.post(
            "/api/v1/tasks/",
            {"title": "Blocked"},
            format="json",
            HTTP_AUTHORIZATION=f"Bearer {v_token}",
            HTTP_X_ORGANIZATION_ID=str(org.id),
        )
        assert viewer_post.status_code == 403

        viewer_patch = v_client.patch(
            f"/api/v1/tasks/{task_id}/",
            {"status": "completed"},
            format="json",
            HTTP_AUTHORIZATION=f"Bearer {v_token}",
            HTTP_X_ORGANIZATION_ID=str(org.id),
        )
        assert viewer_patch.status_code == 403

        # Contributor can PATCH org tasks, but cannot DELETE (requires admin/owner)
        contrib_patch = c_client.patch(
            f"/api/v1/tasks/{task_id}/",
            {"status": "in_progress"},
            format="json",
            HTTP_AUTHORIZATION=f"Bearer {c_token}",
            HTTP_X_ORGANIZATION_ID=str(org.id),
        )
        assert contrib_patch.status_code == 200

        contrib_delete = c_client.delete(
            f"/api/v1/tasks/{task_id}/",
            HTTP_AUTHORIZATION=f"Bearer {c_token}",
            HTTP_X_ORGANIZATION_ID=str(org.id),
        )
        assert contrib_delete.status_code == 403

        # Owner CAN delete the org task
        o_client, o_token = self._jwt_client(owner)
        owner_delete = o_client.delete(
            f"/api/v1/tasks/{task_id}/",
            HTTP_AUTHORIZATION=f"Bearer {o_token}",
            HTTP_X_ORGANIZATION_ID=str(org.id),
        )
        assert owner_delete.status_code == 204

    def test_max_tasks_quota_blocks_creation_but_allows_delete_recovery(self):
        org = Organization.objects.create(name="Quota Org", slug="quota-org", max_tasks=1)
        owner = User.objects.create_user(email="qowner@example.com", password="pw")
        OrganizationMember.objects.create(organization=org, user=owner, role="owner")
        client, token = self._jwt_client(owner)

        # First task succeeds
        r1 = client.post(
            "/api/v1/tasks/",
            {"title": "First"},
            format="json",
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_X_ORGANIZATION_ID=str(org.id),
        )
        assert r1.status_code == 201
        task_id = r1.json()["id"]

        # Second task hits quota -> blocked (403/429)
        r2 = client.post(
            "/api/v1/tasks/",
            {"title": "Second"},
            format="json",
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_X_ORGANIZATION_ID=str(org.id),
        )
        assert r2.status_code in (403, 429)

        # DELETE while at quota must NOT deadlock!
        del_resp = client.delete(
            f"/api/v1/tasks/{task_id}/",
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_X_ORGANIZATION_ID=str(org.id),
        )
        assert del_resp.status_code == 204

        # After soft-deleting, quota slot is freed and creation succeeds again
        r3 = client.post(
            "/api/v1/tasks/",
            {"title": "Replacement"},
            format="json",
            HTTP_AUTHORIZATION=f"Bearer {token}",
            HTTP_X_ORGANIZATION_ID=str(org.id),
        )
        assert r3.status_code == 201


@pytest.mark.django_db
class TestManagementCommandsHardening:
    """Verify idempotent seed_data (with/without Faker) and warm_cache real keys."""

    def test_seed_data_idempotent_and_works_without_faker(self):
        out = StringIO()
        with patch("apps.core.management.commands.seed_data._build_generators", return_value=None):
            call_command("seed_data", users=2, tasks_per_user=2, stdout=out)
            # Re-running must NOT raise IntegrityError or duplicate beyond target count
            call_command("seed_data", users=2, tasks_per_user=2, stdout=out)

        u0 = User.objects.get(email="demo0@example.com")
        assert Task.objects.filter(user=u0).count() == 2

    def test_warm_cache_populates_real_user_and_org_keys(self):
        cache.clear()
        user = User.objects.create_user(email="warm@example.com", password="pw")
        org = Organization.objects.create(name="Warm Org", slug="warm-org")
        OrganizationMember.objects.create(organization=org, user=user, role="owner")

        task = Task.objects.create(user=user, organization=org, status="pending")
        task.set_current_language("en")
        task.title = "Warm Title"
        task.description = "Warm Description"
        task.save()

        out = StringIO()
        call_command("warm_cache", languages=["en", "es"], limit=10, stdout=out)

        user_list_key = f"mltask:task_list:{user.id}:en:"
        user_detail_key = f"mltask:task_detail:{user.id}:en:{task.id}"
        org_list_key = f"mltask:task_list:org:{org.id}:en:"
        assert cache.get(user_list_key) is not None
        assert cache.get(user_list_key)["count"] == 1
        assert cache.get(user_detail_key)["title"] == "Warm Title"
        assert cache.get(org_list_key)["count"] == 1
