"""Tests for Wave 1: Auth lifecycle (/me/, /logout/), Organizations CRUD/RBAC, Audit Logs, and Idempotency-Key."""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.core.cache import cache

import pytest
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.core.models import AuditLog, Organization, OrganizationMember

User = get_user_model()


def _auth_client(user: User) -> APIClient:
    client = APIClient()
    refresh = RefreshToken.for_user(user)
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")
    return client


@pytest.mark.django_db
class TestAuthLifecycle:
    """Verify /api/v1/auth/me/ and /api/v1/auth/logout/ token blacklisting."""

    def test_me_returns_profile_and_active_organizations(self) -> None:
        user = User.objects.create_user(
            email="alice@example.com", password="Password123!", first_name="Alice"
        )
        org = Organization.objects.create(name="Acme AI", slug="acme-ai", plan="pro")
        OrganizationMember.objects.create(organization=org, user=user, role="owner")

        client = _auth_client(user)
        resp = client.get("/api/v1/auth/me/")
        assert resp.status_code == 200
        assert resp.data["email"] == "alice@example.com"
        assert len(resp.data["organizations"]) == 1
        assert resp.data["organizations"][0]["slug"] == "acme-ai"
        assert resp.data["organizations"][0]["role"] == "owner"

        patch_resp = client.patch("/api/v1/auth/me/", {"first_name": "Alicia"}, format="json")
        assert patch_resp.status_code == 200
        assert patch_resp.data["first_name"] == "Alicia"

    def test_me_rejects_xss_in_first_name(self) -> None:
        user = User.objects.create_user(email="xss@example.com", password="Password123!")
        client = _auth_client(user)
        resp = client.patch(
            "/api/v1/auth/me/",
            {"first_name": "<script>alert(1)</script>"},
            format="json",
        )
        assert resp.status_code == 400

    def test_logout_blacklists_own_refresh_token_and_blocks_foreign_token(self) -> None:
        alice = User.objects.create_user(email="alice2@example.com", password="Password123!")
        bob = User.objects.create_user(email="bob2@example.com", password="Password123!")

        alice_refresh = RefreshToken.for_user(alice)
        bob_refresh = RefreshToken.for_user(bob)

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {alice_refresh.access_token}")

        # Attempting to blacklist another user's refresh token must fail with 403
        cross_resp = client.post(
            "/api/v1/auth/logout/", {"refresh": str(bob_refresh)}, format="json"
        )
        assert cross_resp.status_code == 403

        # Blacklisting own refresh token succeeds and records AuditLog
        ok_resp = client.post(
            "/api/v1/auth/logout/", {"refresh": str(alice_refresh)}, format="json"
        )
        assert ok_resp.status_code == 200
        assert AuditLog.objects.filter(user=alice, action="logout").exists()

        # Subsequent refresh attempt with blacklisted token must fail
        refresh_resp = APIClient().post(
            "/api/v1/auth/token/refresh/",
            {"refresh": str(alice_refresh)},
            format="json",
        )
        assert refresh_resp.status_code == 401


@pytest.mark.django_db
class TestOrganizationSelfServeAndRBAC:
    """Verify /api/v1/organizations/ CRUD, seat quotas, privilege guards, and audit logs."""

    def test_create_org_invite_members_seat_limit_and_last_owner_guard(self) -> None:
        owner = User.objects.create_user(email="owner@org.io", password="Password123!")
        admin_user = User.objects.create_user(email="admin@org.io", password="Password123!")
        viewer_user = User.objects.create_user(email="viewer@org.io", password="Password123!")
        User.objects.create_user(email="extra@org.io", password="Password123!")

        owner_client = _auth_client(owner)
        create_resp = owner_client.post(
            "/api/v1/organizations/",
            {"name": "Scale Lab", "slug": "scale-lab"},
            format="json",
        )
        assert create_resp.status_code == 201
        org_id = create_resp.data["id"]
        assert create_resp.data["my_role"] == "owner"

        # Tighten max_users to 3 to test seat-limit enforcement
        Organization.objects.filter(id=org_id).update(max_users=3)

        # Invite admin_user and viewer_user (fills 3/3 seats)
        r1 = owner_client.post(
            f"/api/v1/organizations/{org_id}/members/",
            {"email": "admin@org.io", "role": "admin"},
            format="json",
        )
        assert r1.status_code == 201
        admin_member_id = r1.data["id"]

        r2 = owner_client.post(
            f"/api/v1/organizations/{org_id}/members/",
            {"email": "viewer@org.io", "role": "viewer"},
            format="json",
        )
        assert r2.status_code == 201
        viewer_member_id = r2.data["id"]

        # 4th user exceeds max_users=3 -> 403 Forbidden
        r_quota = owner_client.post(
            f"/api/v1/organizations/{org_id}/members/",
            {"email": "extra@org.io", "role": "viewer"},
            format="json",
        )
        assert r_quota.status_code == 403

        # Admin cannot escalate anyone to owner
        admin_client = _auth_client(admin_user)
        r_esc = admin_client.patch(
            f"/api/v1/organizations/{org_id}/members/{viewer_member_id}/",
            {"role": "owner"},
            format="json",
        )
        assert r_esc.status_code == 403

        # Cannot remove or demote the sole owner
        owner_member = OrganizationMember.objects.get(organization_id=org_id, user=owner)
        r_demote = owner_client.patch(
            f"/api/v1/organizations/{org_id}/members/{owner_member.id}/",
            {"role": "admin"},
            format="json",
        )
        assert r_demote.status_code == 400
        r_del_owner = owner_client.delete(
            f"/api/v1/organizations/{org_id}/members/{owner_member.id}/"
        )
        assert r_del_owner.status_code == 400

        # Viewer cannot view organization audit logs (403), but admin/owner can (200)
        viewer_client = _auth_client(viewer_user)
        assert viewer_client.get(f"/api/v1/organizations/{org_id}/audit-logs/").status_code == 403

        audit_resp = admin_client.get(
            f"/api/v1/organizations/{org_id}/audit-logs/?action=permission_changed"
        )
        assert audit_resp.status_code == 200
        assert audit_resp.data["count"] >= 2

        # Admin can remove viewer_user freeing a seat
        del_resp = admin_client.delete(
            f"/api/v1/organizations/{org_id}/members/{viewer_member_id}/"
        )
        assert del_resp.status_code == 204
        assert admin_member_id is not None


@pytest.mark.django_db
class TestIdempotencyKeyMiddleware:
    """Verify Redis-backed Idempotency-Key deduplication, conflict, and body-mismatch guards."""

    def setup_method(self) -> None:
        cache.clear()

    def test_idempotent_task_creation_replay_and_payload_mismatch(self) -> None:
        user_a = User.objects.create_user(email="idem-a@org.io", password="Password123!")
        user_b = User.objects.create_user(email="idem-b@org.io", password="Password123!")
        client_a = _auth_client(user_a)
        client_b = _auth_client(user_b)

        payload = {"title": "Evaluate safety prompt", "description": "Run once"}
        first = client_a.post(
            "/api/v1/tasks/",
            payload,
            format="json",
            HTTP_IDEMPOTENCY_KEY="idem-key-001",
        )
        assert first.status_code == 201
        assert first.headers.get("X-Idempotency-Replayed") == "false"

        # Exact retry returns cached 201 without creating a duplicate task
        second = client_a.post(
            "/api/v1/tasks/",
            payload,
            format="json",
            HTTP_IDEMPOTENCY_KEY="idem-key-001",
        )
        assert second.status_code == 201
        assert second.headers.get("X-Idempotency-Replayed") == "true"
        assert second.json()["id"] == first.json()["id"]
        assert user_a.tasks.count() == 1

        # Reusing same Idempotency-Key with mutated payload returns 422
        mismatch = client_a.post(
            "/api/v1/tasks/",
            {"title": "Different payload", "description": "Mutated"},
            format="json",
            HTTP_IDEMPOTENCY_KEY="idem-key-001",
        )
        assert mismatch.status_code == 422

        # Different user with same Idempotency-Key string has isolated namespace
        other_user_resp = client_b.post(
            "/api/v1/tasks/",
            payload,
            format="json",
            HTTP_IDEMPOTENCY_KEY="idem-key-001",
        )
        assert other_user_resp.status_code == 201
        assert other_user_resp.json()["id"] != first.json()["id"]

        # Oversized Idempotency-Key (>128 chars) is rejected with 400
        too_long = client_a.post(
            "/api/v1/tasks/",
            payload,
            format="json",
            HTTP_IDEMPOTENCY_KEY="k" * 140,
        )
        assert too_long.status_code == 400
