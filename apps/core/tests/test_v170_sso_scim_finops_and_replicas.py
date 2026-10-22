"""Tests for v1.7.0 OIDC SSO, SCIM 2.0 provisioning, AI FinOps budgets, and read-replica routing."""

from __future__ import annotations

import json
import time
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db import connections, transaction
from django.utils import timezone

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.core.db_router import ReplicaDatabaseRouter, resolve_read_db_alias, use_read_replica
from apps.core.finops import AIBudgetExceededError, enforce_org_ai_budget, get_monthly_org_ai_burn
from apps.core.models import (
    AIUsageLog,
    AuditLog,
    Organization,
    OrganizationAPIKey,
    OrganizationMember,
    OrganizationSSOConfig,
    OutboxEvent,
)
from apps.core.views import record_ai_token_usage
from apps.tasks.models import Task, TaskAnnotation
from apps.tasks.tasks import generate_task_translations

User = get_user_model()


def _generate_rsa_keypair_and_jwk(kid: str = "idp-key-2026") -> tuple[Any, dict[str, Any], str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_key = private_key.public_key()
    jwk_dict = json.loads(RSAAlgorithm.to_jwk(pub_key))
    jwk_dict["kid"] = kid
    jwk_dict["use"] = "sig"
    jwk_dict["alg"] = "RS256"
    pub_pem = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_key, jwk_dict, pub_pem


def _mint_oidc_id_token(
    private_key: Any,
    *,
    kid: str | None = "idp-key-2026",
    iss: str = "https://idp.acme.ai",
    aud: str = "mltask-enterprise-client",
    sub: str = "oidc-sub-001",
    email: str = "claire@acme.ai",
    email_verified: bool = True,
    groups: list[str] | str | None = None,
    given_name: str = "Claire",
    family_name: str = "Laurent",
) -> str:
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": iss,
        "aud": aud,
        "sub": sub,
        "email": email,
        "email_verified": email_verified,
        "given_name": given_name,
        "family_name": family_name,
        "iat": now - 5,
        "exp": now + 600,
    }
    if groups is not None:
        claims["groups"] = groups
    headers = {"kid": kid} if kid else None
    return str(
        jwt.encode(
            claims,
            private_key,
            algorithm="RS256",
            headers=headers,
        )
    )


def _auth_client(user: Any, org: Organization | None = None) -> APIClient:
    client = APIClient()
    access = str(RefreshToken.for_user(user).access_token)
    creds: dict[str, str] = {"HTTP_AUTHORIZATION": f"Bearer {access}"}
    if org is not None:
        creds["HTTP_X_ORGANIZATION_ID"] = str(org.id)
    client.credentials(**creds)
    return client


@pytest.mark.django_db
class TestEnterpriseOIDCSSOExchange:
    """Verify OIDC configuration RBAC, RS256 JWKS/PEM verification, JIT provisioning, and attack defenses."""

    def test_oidc_config_jit_exchange_pem_fallback_and_key_confusion_defenses(self) -> None:
        cache.clear()
        owner = User.objects.create_user(email="owner@acme.ai", password="pw")
        viewer = User.objects.create_user(email="viewer@acme.ai", password="pw")
        org = Organization.objects.create(
            name="Acme AI",
            slug="acme-ai",
            plan="enterprise",
            max_users=3,
        )
        OrganizationMember.objects.create(organization=org, user=owner, role="owner")
        OrganizationMember.objects.create(organization=org, user=viewer, role="viewer")

        priv_key, jwk_dict, pub_pem = _generate_rsa_keypair_and_jwk()

        # Non-admin member cannot read or modify SSO config
        viewer_client = _auth_client(viewer, org)
        assert viewer_client.get(f"/api/v1/organizations/{org.id}/sso/").status_code == 403

        owner_client = _auth_client(owner, org)
        assert owner_client.get(f"/api/v1/organizations/{org.id}/sso/").status_code == 200

        # Non-HTTPS issuer, bad domain, and owner role_mapping target are rejected
        assert (
            owner_client.patch(
                f"/api/v1/organizations/{org.id}/sso/",
                {"oidc_issuer": "http://insecure.acme.ai"},
                format="json",
            ).status_code
            == 400
        )
        assert (
            owner_client.patch(
                f"/api/v1/organizations/{org.id}/sso/",
                {"allowed_domains": ["not-a-domain"]},
                format="json",
            ).status_code
            == 400
        )
        assert (
            owner_client.patch(
                f"/api/v1/organizations/{org.id}/sso/",
                {"role_mapping": {"execs": "owner"}},
                format="json",
            ).status_code
            == 400
        )

        # Configure RS256 JWKS, domain allowlist, and RLHF persona role mapping
        cfg_resp = owner_client.patch(
            f"/api/v1/organizations/{org.id}/sso/",
            {
                "enabled": True,
                "oidc_issuer": "https://idp.acme.ai",
                "oidc_client_id": "mltask-enterprise-client",
                "jwks_json": {"keys": [jwk_dict]},
                "allowed_domains": ["acme.ai"],
                "role_claim": "groups",
                "role_mapping": {
                    "rlhf-annotators": "annotator",
                    "ml-platform-admins": "admin",
                },
                "default_role": "viewer",
                "jit_provisioning": True,
            },
            format="json",
        )
        assert cfg_resp.status_code == 200
        assert "scim_token_hash" not in cfg_resp.json()
        assert AuditLog.objects.filter(organization=org, action="sso_updated").count() == 1

        anon_client = APIClient()

        # Unknown slug -> 404
        assert (
            anon_client.post(
                "/api/v1/auth/sso/oidc/exchange/",
                {"organization_slug": "missing-org", "id_token": "tok"},
                format="json",
            ).status_code
            == 404
        )

        # 1. Valid RS256 token JIT-provisions user with unusable password + mapped contributor role
        valid_token = _mint_oidc_id_token(
            priv_key,
            email="claire@acme.ai",
            groups=["rlhf-annotators"],
        )
        ex_resp = anon_client.post(
            "/api/v1/auth/sso/oidc/exchange/",
            {"organization_slug": "acme-ai", "id_token": valid_token},
            format="json",
        )
        assert ex_resp.status_code == 200
        ex_data = ex_resp.json()
        assert ex_data["role"] == "contributor"
        assert ex_data["organization_id"] == str(org.id)

        claire = User.objects.get(email="claire@acme.ai")
        assert not claire.has_usable_password()
        assert AuditLog.objects.filter(organization=org, action="sso_login", user=claire).exists()

        # Seat limit now full (3/3: owner, viewer, claire) -> 4th JIT user receives 403
        fourth_token = _mint_oidc_id_token(priv_key, email="fourth@acme.ai", sub="sub-4")
        assert (
            anon_client.post(
                "/api/v1/auth/sso/oidc/exchange/",
                {"organization_slug": "acme-ai", "id_token": fourth_token},
                format="json",
            ).status_code
            == 403
        )

        # Switch to PEM public key verification + jit_provisioning=False
        owner_client.patch(
            f"/api/v1/organizations/{org.id}/sso/",
            {
                "jwks_json": {},
                "public_key_pem": pub_pem,
                "jit_provisioning": False,
            },
            format="json",
        )

        # Existing member Claire signs in via PEM public key & scalar group string -> promoted to admin
        pem_token = _mint_oidc_id_token(
            priv_key,
            kid=None,
            email="claire@acme.ai",
            groups="ml-platform-admins",
            given_name="Claire-Marie",
        )
        pem_resp = anon_client.post(
            "/api/v1/auth/sso/oidc/exchange/",
            {"organization_slug": "acme-ai", "id_token": pem_token},
            format="json",
        )
        assert pem_resp.status_code == 200
        assert pem_resp.json()["role"] == "admin"
        assert pem_resp.json()["user"]["first_name"] == "Claire-Marie"

        # Non-provisioned user blocked when jit_provisioning=False
        unjit_token = _mint_oidc_id_token(priv_key, kid=None, email="newhire@acme.ai")
        assert (
            anon_client.post(
                "/api/v1/auth/sso/oidc/exchange/",
                {"organization_slug": "acme-ai", "id_token": unjit_token},
                format="json",
            ).status_code
            == 403
        )

        # Owner signing in via OIDC keeps owner role
        owner_sso_token = _mint_oidc_id_token(
            priv_key,
            kid=None,
            sub="oidc-owner",
            email="owner@acme.ai",
            groups=["rlhf-annotators"],
        )
        owner_sso_resp = anon_client.post(
            "/api/v1/auth/sso/oidc/exchange/",
            {"organization_slug": "acme-ai", "id_token": owner_sso_token},
            format="json",
        )
        assert owner_sso_resp.status_code == 200
        assert owner_sso_resp.json()["role"] == "owner"

        # Adversarial checks: HS256 key confusion, wrong audience, disallowed domain, unverified email
        hs256_forged = jwt.encode(
            {
                "iss": "https://idp.acme.ai",
                "aud": "mltask-enterprise-client",
                "sub": "attacker",
                "email": "attacker@acme.ai",
                "iat": int(time.time()) - 5,
                "exp": int(time.time()) + 300,
            },
            "symmetric-secret-attempt-0123456789abcdef",
            algorithm="HS256",
        )
        assert (
            anon_client.post(
                "/api/v1/auth/sso/oidc/exchange/",
                {"organization_slug": "acme-ai", "id_token": hs256_forged},
                format="json",
            ).status_code
            == 401
        )
        wrong_aud = _mint_oidc_id_token(priv_key, kid=None, aud="wrong-client")
        assert (
            anon_client.post(
                "/api/v1/auth/sso/oidc/exchange/",
                {"organization_slug": "acme-ai", "id_token": wrong_aud},
                format="json",
            ).status_code
            == 401
        )
        bad_domain_token = _mint_oidc_id_token(priv_key, kid=None, email="intruder@evil.org")
        assert (
            anon_client.post(
                "/api/v1/auth/sso/oidc/exchange/",
                {"organization_slug": "acme-ai", "id_token": bad_domain_token},
                format="json",
            ).status_code
            == 403
        )
        unverified_token = _mint_oidc_id_token(
            priv_key,
            kid=None,
            email="claire@acme.ai",
            email_verified=False,
        )
        assert (
            anon_client.post(
                "/api/v1/auth/sso/oidc/exchange/",
                {"organization_slug": "acme-ai", "id_token": unverified_token},
                format="json",
            ).status_code
            == 401
        )


@pytest.mark.django_db
class TestSCIM20LifecycleAndMultiTenantOffboarding:
    """Verify RFC 7643/7644 SCIM 2.0 provisioning, filtering, PUT/PATCH, and safe offboarding."""

    def test_scim_v2_users_crud_put_patch_offboarding_and_cross_tenant_isolation(self) -> None:
        cache.clear()
        owner_a = User.objects.create_user(email="owner-a@acme.ai", password="pw")
        owner_b = User.objects.create_user(email="owner-b@beta.ai", password="pw")
        org_a = Organization.objects.create(
            name="Org A",
            slug="scim-org-a",
            plan="enterprise",
            max_users=10,
        )
        org_b = Organization.objects.create(
            name="Org B",
            slug="scim-org-b",
            plan="enterprise",
            max_users=10,
        )
        owner_member_a = OrganizationMember.objects.create(
            organization=org_a,
            user=owner_a,
            role="owner",
        )
        OrganizationMember.objects.create(organization=org_b, user=owner_b, role="owner")

        # Missing & malformed SCIM Bearer credentials return 401 SCIM Error
        unauth_scim = APIClient()
        assert unauth_scim.get(f"/api/v1/organizations/{org_a.id}/scim/v2/Users").status_code == 401
        unauth_scim.credentials(HTTP_AUTHORIZATION="Bearer malformed_token")
        assert unauth_scim.get(f"/api/v1/organizations/{org_a.id}/scim/v2/Users").status_code == 401

        admin_client_a = _auth_client(owner_a, org_a)
        admin_client_a.patch(
            f"/api/v1/organizations/{org_a.id}/sso/",
            {
                "allowed_domains": ["acme.ai"],
                "default_role": "viewer",
                "role_mapping": {"qa-leads": "admin"},
            },
            format="json",
        )
        rot_resp = admin_client_a.post(f"/api/v1/organizations/{org_a.id}/sso/scim-token/")
        assert rot_resp.status_code == 201
        scim_token = rot_resp.json()["scim_token"]
        assert scim_token.startswith("scim_live_")

        scim_client = APIClient()
        scim_client.credentials(HTTP_AUTHORIZATION=f"Bearer {scim_token}")

        # Org A's SCIM token is strictly rejected on Org B
        cross_resp = scim_client.get(f"/api/v1/organizations/{org_b.id}/scim/v2/Users")
        assert cross_resp.status_code == 401
        assert "urn:ietf:params:scim:api:messages:2.0:Error" in cross_resp.json()["schemas"]

        # 1. Provision single-tenant user via POST /scim/v2/Users (emails[] fallback + role_mapping)
        create_resp = scim_client.post(
            f"/api/v1/organizations/{org_a.id}/scim/v2/Users",
            {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "externalId": "okta-user-900",
                "emails": [{"value": "devon@acme.ai", "primary": True}],
                "name": {"givenName": "Devon", "familyName": "Patel"},
                "active": True,
                "roles": [{"value": "reviewer", "primary": True}],
            },
            format="json",
        )
        assert create_resp.status_code == 201
        created_scim = create_resp.json()
        devon_member_id = created_scim["id"]
        assert created_scim["roles"][0]["value"] == "contributor"

        # Idempotent re-POST updates existing member and returns 200 OK
        repost_resp = scim_client.post(
            f"/api/v1/organizations/{org_a.id}/scim/v2/Users",
            {
                "userName": "devon@acme.ai",
                "externalId": "okta-user-901",
                "roles": [{"value": "qa-leads"}],
            },
            format="json",
        )
        assert repost_resp.status_code == 200
        assert repost_resp.json()["roles"][0]["value"] == "admin"

        # Retrieve single SCIM User resource
        detail_resp = scim_client.get(
            f"/api/v1/organizations/{org_a.id}/scim/v2/Users/{devon_member_id}"
        )
        assert detail_resp.status_code == 200
        assert detail_resp.json()["externalId"] == "okta-user-901"

        devon = User.objects.get(email="devon@acme.ai")
        devon_key, _ = OrganizationAPIKey.create_with_raw_key(
            organization=org_a,
            created_by=devon,
            name="Devon Pipeline Key",
            role="contributor",
        )

        # 2. Filter by userName and externalId
        by_uname = scim_client.get(
            f"/api/v1/organizations/{org_a.id}/scim/v2/Users",
            {"filter": 'userName eq "devon@acme.ai"'},
        )
        assert by_uname.status_code == 200
        assert by_uname.json()["totalResults"] == 1

        by_ext = scim_client.get(
            f"/api/v1/organizations/{org_a.id}/scim/v2/Users",
            {"filter": 'externalId eq "okta-user-901"'},
        )
        assert by_ext.status_code == 200
        assert by_ext.json()["totalResults"] == 1

        bad_filter = scim_client.get(
            f"/api/v1/organizations/{org_a.id}/scim/v2/Users",
            {"filter": "invalid SQL injection attempt"},
        )
        assert bad_filter.status_code == 400
        assert bad_filter.json()["scimType"] == "invalidFilter"

        # 3. PUT full replacement + root-dict PATCH update
        put_resp = scim_client.put(
            f"/api/v1/organizations/{org_a.id}/scim/v2/Users/{devon_member_id}",
            {
                "externalId": "okta-user-902",
                "name": {"givenName": "Dev", "familyName": "Patel-Smith"},
                "roles": ["contributor"],
                "active": True,
            },
            format="json",
        )
        assert put_resp.status_code == 200
        assert put_resp.json()["roles"][0]["value"] == "contributor"
        assert put_resp.json()["name"]["familyName"] == "Patel-Smith"

        # 4. Root-dict PatchOp active=false offboards Devon, revokes API key, disables orphan user
        offboard_resp = scim_client.patch(
            f"/api/v1/organizations/{org_a.id}/scim/v2/Users/{devon_member_id}",
            {
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [{"op": "replace", "value": {"active": False}}],
            },
            format="json",
        )
        assert offboard_resp.status_code == 200
        assert offboard_resp.json()["active"] is False
        devon.refresh_from_db()
        devon_key.refresh_from_db()
        assert devon.is_active is False
        assert devon_key.revoked_at is not None
        assert OutboxEvent.objects.filter(
            organization=org_a,
            event_type="scim.user_deprovisioned",
        ).exists()

        # 5. Multi-tenant user in both Org A and Org B keeps user.is_active=True when removed from Org A
        shared_user = User.objects.create_user(email="shared@acme.ai", password="pw")
        OrganizationMember.objects.create(organization=org_b, user=shared_user, role="contributor")
        shared_prov = scim_client.post(
            f"/api/v1/organizations/{org_a.id}/scim/v2/Users/",
            {"userName": "shared@acme.ai", "roles": ["viewer"]},
            format="json",
        )
        assert shared_prov.status_code == 201
        shared_member_id = shared_prov.json()["id"]

        del_resp = scim_client.delete(
            f"/api/v1/organizations/{org_a.id}/scim/v2/Users/{shared_member_id}/"
        )
        assert del_resp.status_code == 204
        shared_user.refresh_from_db()
        assert shared_user.is_active is True

        # 6. Last owner cannot be deprovisioned via SCIM
        last_owner_del = scim_client.delete(
            f"/api/v1/organizations/{org_a.id}/scim/v2/Users/{owner_member_a.id}"
        )
        assert last_owner_del.status_code == 400
        assert last_owner_del.json()["scimType"] == "mutability"


@pytest.mark.django_db
class TestTenantAIFinOpsBudgetsAndAlerts:
    """Verify monthly AI token/cost ceilings, deduplicated Outbox alerts, and Redis-loss recovery."""

    def test_finops_budget_thresholds_outbox_alerts_hard_cutoff_and_db_rehydration(self) -> None:
        cache.clear()
        owner = User.objects.create_user(email="finops@acme.ai", password="pw")
        org = Organization.objects.create(
            name="FinOps Org",
            slug="finops-org",
            plan="starter",
            max_users=10,
        )
        OrganizationMember.objects.create(organization=org, user=owner, role="owner")

        client = _auth_client(owner, org)

        # Configure tight 1,000-token monthly budget with 80% warning threshold
        patch_resp = client.patch(
            f"/api/v1/organizations/{org.id}/finops/",
            {
                "monthly_ai_token_budget": 1000,
                "monthly_ai_cost_budget_microusd": 10_000_000,
                "ai_budget_alert_threshold_pct": 80,
            },
            format="json",
        )
        assert patch_resp.status_code == 200
        assert patch_resp.headers["X-Query-Target"] == "primary"
        assert AuditLog.objects.filter(organization=org, action="finops_budget_updated").exists()

        # 1. Burn 820 tokens (82%) -> crosses 80% threshold once
        record_ai_token_usage(
            600,
            220,
            str(org.id),
            user_id=str(owner.id),
            operation="suggest_task_translations",
        )
        assert (
            OutboxEvent.objects.filter(
                organization=org,
                event_type="ai.budget_threshold_reached",
            ).count()
            == 1
        )
        assert (
            OutboxEvent.objects.filter(
                organization=org,
                event_type="ai.budget_exceeded",
            ).count()
            == 0
        )

        # 2. Burn 80 more tokens (900 / 1000 = 90%) -> threshold alert must NOT duplicate
        record_ai_token_usage(
            50,
            30,
            str(org.id),
            user_id=str(owner.id),
            operation="evaluate_prompt_quality",
        )
        assert (
            OutboxEvent.objects.filter(
                organization=org,
                event_type="ai.budget_threshold_reached",
            ).count()
            == 1
        )

        # 3. Burn 150 more tokens (1050 / 1000 = 105%) -> crosses 100% hard ceiling
        record_ai_token_usage(
            100,
            50,
            str(org.id),
            user_id=str(owner.id),
            operation="suggest_task_translations",
        )
        assert (
            OutboxEvent.objects.filter(
                organization=org,
                event_type="ai.budget_exceeded",
            ).count()
            == 1
        )
        assert AIUsageLog.objects.filter(organization=org).count() == 3

        # 4. All 3 AI Assist endpoints block uncached calls with 429 before hitting OpenAI
        with patch("apps.ai_assist.services.AIService._call_llm") as mock_llm:
            sug_resp = client.post(
                "/api/v1/ai/suggest-task/",
                {"description": "Translate quantum alignment benchmark dataset"},
                format="json",
            )
            assert sug_resp.status_code == 429
            assert sug_resp.json()["code"] == "ai_budget_exceeded"
            assert sug_resp.json()["budget"]["tokens_used"] == 1050

            eval_resp = client.post(
                "/api/v1/ai/evaluate-quality/",
                {"prompt_text": "Evaluate rubric precision across 3 target locales"},
                format="json",
            )
            assert eval_resp.status_code == 429

            rlhf_resp = client.post(
                "/api/v1/ai/generate-test-cases/",
                {"code_snippet": "def score_preference(a: int, b: int) -> int:\n    return a - b"},
                format="json",
            )
            assert rlhf_resp.status_code == 429
            mock_llm.assert_not_called()

        # 5. Background Celery auto-translate gracefully skips without retry storms
        task = Task.objects.create(user=owner, organization=org, status="pending")
        task.set_current_language("en")
        task.title = "Budget exhausted task"
        task.save()
        assert generate_task_translations(str(task.id), "Budget exhausted task") == {}

        # 6. Simulate complete Redis flush -> FinOps rollups rehydrate from AIUsageLog SQL ledger
        cache.clear()
        tok_used, _cost_nano = get_monthly_org_ai_burn(str(org.id))
        assert tok_used == 1050
        with pytest.raises(AIBudgetExceededError) as exc_info:
            enforce_org_ai_budget(str(org.id))
        assert exc_info.value.budget_snapshot["reason"] == "token_budget_exceeded"

        # 7. FinOps reporting & /usage/ endpoints return accurate rollups and X-Query-Target header
        finops_resp = client.get(f"/api/v1/organizations/{org.id}/finops/")
        assert finops_resp.status_code == 200
        assert finops_resp.headers["X-Query-Target"] == "primary"
        body = finops_resp.json()
        assert body["current_usage"]["tokens_used"] == 1050
        assert body["current_usage"]["budget_exceeded"] is True
        ops = {row["operation"]: row["total_tokens"] for row in body["by_operation"]}
        assert ops["suggest_task_translations"] == 970
        assert ops["evaluate_prompt_quality"] == 80

        usage_resp = client.get(f"/api/v1/organizations/{org.id}/usage/")
        assert usage_resp.status_code == 200
        assert usage_resp.headers["X-Query-Target"] == "primary"


@pytest.mark.django_db
class TestReadReplicaRoutingAndTaskStats:
    """Verify /api/v1/tasks/stats/ aggregations and ReplicaDatabaseRouter transaction pinning."""

    def test_task_stats_endpoint_and_replica_router_semantics(self) -> None:
        cache.clear()
        owner = User.objects.create_user(email="stats@acme.ai", password="pw")
        annotator = User.objects.create_user(email="ann@acme.ai", password="pw")
        other_user = User.objects.create_user(email="outsider@beta.ai", password="pw")
        org = Organization.objects.create(name="Stats Org", slug="stats-org", plan="professional")
        OrganizationMember.objects.create(organization=org, user=owner, role="owner")
        OrganizationMember.objects.create(organization=org, user=annotator, role="contributor")

        t1 = Task.objects.create(
            user=owner,
            organization=org,
            status="completed",
            priority="critical",
            consensus_choice="a",
            consensus_score=1.0,
        )
        t2 = Task.objects.create(
            user=owner,
            organization=org,
            status="in_progress",
            priority="high",
            claimed_by=annotator,
            claimed_until=timezone.now() + timezone.timedelta(minutes=10),
        )
        TaskAnnotation.objects.create(
            task=t1,
            annotator=annotator,
            preference="a",
            rationale="Accurate formal register across all clauses.",
        )
        # Outsider personal task must never appear in Org stats, but appears in outsider's personal stats
        Task.objects.create(user=other_user, status="pending", priority="low")

        client = _auth_client(owner, org)
        stats_resp = client.get("/api/v1/tasks/stats/")
        assert stats_resp.status_code == 200
        assert stats_resp.headers["X-Query-Target"] == "primary"
        stats_data = stats_resp.json()
        assert stats_data["total_tasks"] == 2
        assert stats_data["by_status"]["completed"] == 1
        assert stats_data["by_status"]["in_progress"] == 1
        assert stats_data["by_priority"]["critical"] == 1
        assert stats_data["by_priority"]["high"] == 1
        assert stats_data["consensus_finalized"] == 1
        assert stats_data["active_leases"] == 1
        assert stats_data["total_annotations"] == 1
        assert t2.id is not None

        outsider_client = _auth_client(other_user)
        personal_stats = outsider_client.get("/api/v1/tasks/stats/")
        assert personal_stats.status_code == 200
        assert personal_stats.json()["total_tasks"] == 1

        # Verify ReplicaDatabaseRouter pins writes & migrations to 'default' and allows cross-alias relations
        router = ReplicaDatabaseRouter()
        assert router.db_for_write(Task) == "default"
        assert router.allow_migrate("default", "tasks") is True
        assert router.allow_migrate("replica", "tasks") is False
        assert (
            router.allow_relation(
                SimpleNamespace(_state=SimpleNamespace(db="default")),
                SimpleNamespace(_state=SimpleNamespace(db="replica")),
            )
            is True
        )
        assert (
            router.allow_relation(
                SimpleNamespace(_state=SimpleNamespace(db="external")),
                SimpleNamespace(_state=SimpleNamespace(db="default")),
            )
            is None
        )
        assert OrganizationSSOConfig._meta.default_manager.db == "default"

        with transaction.atomic():
            with use_read_replica() as target:
                assert target == "primary"
                assert resolve_read_db_alias() == "default"
        assert "default" in connections.databases
