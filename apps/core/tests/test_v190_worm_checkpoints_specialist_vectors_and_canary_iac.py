"""Comprehensive v1.9.0 test suite covering:
1. External Anchoring & WORM S3 Object-Lock Checkpointing (AWS SigV4 PUT, root-replacement & signature tamper detection, Celery Beat sweep).
2. Multi-Dimensional Domain/Language Skill Vectors, Specialist Claim Routing & Expert Probation Gating.
3. Terraform S3 Object-Lock WORM Bucket, ECS/Celery Autoscaling & CloudWatch Canary Rollback IaC.
"""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.test import override_settings

import pytest
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.core.audit_chain import GENESIS_AUDIT_HASH, compute_audit_entry_hash
from apps.core.models import (
    AuditChainCheckpoint,
    AuditLog,
    Organization,
    OrganizationMember,
    OutboxEvent,
)
from apps.tasks.calibration import compute_bayesian_skill_weight
from apps.tasks.models import AnnotatorCalibration
from apps.tasks.tasks import anchor_audit_chain_checkpoints

User = get_user_model()


def _auth_client(user: object, org: Organization | None = None) -> APIClient:
    client = APIClient()
    token = str(RefreshToken.for_user(user).access_token)  # type: ignore[arg-type]
    creds: dict[str, str] = {"HTTP_AUTHORIZATION": f"Bearer {token}"}
    if org is not None:
        creds["HTTP_X_ORGANIZATION_ID"] = str(org.id)
    client.credentials(**creds)
    return client


@pytest.mark.django_db
class TestAuditWORMCheckpointsAndRootReplacementDefense:
    """Verify HMAC + S3 Object-Lock WORM checkpoints and root-replacement tamper detection."""

    @override_settings(
        AUDIT_ANCHOR_SIGNING_KEY="v190-test-anchor-kms-secret-key",
        AUDIT_WORM_S3_BUCKET="mltask-worm-test-bucket",
        AUDIT_WORM_S3_REGION="us-east-1",
        AUDIT_WORM_RETENTION_DAYS=365,
    )
    def test_s3_worm_sigv4_upload_immutability_and_rbac(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
        monkeypatch.setenv("AWS_SESSION_TOKEN", "AQoDYXdzEJr123SessionToken")

        owner = User.objects.create_user(email="worm-owner@example.com", password="Password123!")
        contrib = User.objects.create_user(
            email="worm-contrib@example.com", password="Password123!"
        )
        outsider = User.objects.create_user(email="worm-out@example.com", password="Password123!")
        org = Organization.objects.create(
            name="WORM Vault Org", slug="worm-vault-org", plan="enterprise"
        )
        OrganizationMember.objects.create(organization=org, user=owner, role="owner")
        OrganizationMember.objects.create(organization=org, user=contrib, role="contributor")

        for idx in range(1, 4):
            AuditLog.objects.create(
                organization=org,
                user=owner,
                action="created",
                resource_type="Task",
                resource_id=f"worm-t-{idx}",
                metadata={"n": idx},
            )

        owner_client = _auth_client(owner, org)
        contrib_client = _auth_client(contrib, org)
        outsider_client = _auth_client(outsider)
        url = f"/api/v1/organizations/{org.id}/audit-logs/checkpoints/"

        assert contrib_client.get(url).status_code == 403
        assert contrib_client.post(url, {}, format="json").status_code == 403
        assert outsider_client.get(url).status_code == 404

        captured_req: dict[str, Any] = {}
        mock_conn = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b""
        mock_resp.getheader.side_effect = lambda h: {
            "ETag": '"d41d8cd98f00b204e9800998ecf8427e"',
            "x-amz-version-id": "v-worm-0001",
        }.get(h)

        def _capture_put(method: str, uri: str, body: bytes, headers: dict[str, str]) -> None:
            captured_req["method"] = method
            captured_req["uri"] = uri
            captured_req["body"] = body
            captured_req["headers"] = headers

        mock_conn.request.side_effect = _capture_put
        mock_conn.getresponse.return_value = mock_resp

        with patch("apps.core.audit_chain.http.client.HTTPSConnection", return_value=mock_conn):
            create_resp = owner_client.post(url, {}, format="json")

        assert create_resp.status_code == 201
        ckpt_json = create_resp.json()
        assert ckpt_json["checkpoint_seq"] == 1
        assert ckpt_json["covered_up_to_seq"] == 3
        assert ckpt_json["anchor_status"] == "s3_worm_locked"
        assert ckpt_json["worm_uri"].startswith(
            f"s3://mltask-worm-test-bucket/audit-checkpoints/{org.id}/seq-00000001-"
        )
        assert ckpt_json["worm_etag"] == "d41d8cd98f00b204e9800998ecf8427e"
        assert ckpt_json["worm_version_id"] == "v-worm-0001"

        # Verify AWS SigV4 + S3 Object Lock COMPLIANCE headers on the wire
        headers = captured_req["headers"]
        assert captured_req["method"] == "PUT"
        assert headers["Authorization"].startswith(
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/"
        )
        assert "x-amz-object-lock-mode" in headers["Authorization"]
        assert headers["x-amz-object-lock-mode"] == "COMPLIANCE"
        assert "x-amz-object-lock-retain-until-date" in headers
        assert headers["x-amz-security-token"] == "AQoDYXdzEJr123SessionToken"
        expected_md5 = base64.b64encode(
            hashlib.md5(captured_req["body"], usedforsecurity=False).digest()
        ).decode("ascii")
        assert headers["Content-MD5"] == expected_md5
        assert OutboxEvent.objects.filter(
            organization=org, event_type="audit.checkpoint_anchored"
        ).exists()

        # Note: creating checkpoint_1 wrote an `audit_checkpoint_anchored` AuditLog (seq 4);
        # anchoring once more covers seq 4, and the subsequent call is a true idempotent 200 hit!
        with patch("apps.core.audit_chain.http.client.HTTPSConnection", return_value=mock_conn):
            second_resp = owner_client.post(url, {}, format="json")
            assert second_resp.status_code == 201
            assert second_resp.json()["checkpoint_seq"] == 2
            # Wait: recording audit_checkpoint_anchored for seq 2 adds seq 5; test Beat sweep idempotency!
            sweep_1 = anchor_audit_chain_checkpoints(batch_size=25)
            sweep_2 = anchor_audit_chain_checkpoints(batch_size=25)
        assert sweep_1["anchored"] == 1
        assert sweep_2["anchored"] == 0
        assert sweep_2["skipped"] == 1

        list_resp = owner_client.get(url)
        assert list_resp.status_code == 200
        assert list_resp.headers["X-Query-Target"] == "primary"
        assert list_resp.json()["count"] == 3

        ckpt_obj = AuditChainCheckpoint.objects.filter(organization=org).first()
        assert ckpt_obj is not None
        ckpt_obj.worm_uri = "s3://tampered/uri"
        with pytest.raises(ValidationError, match="immutable"):
            ckpt_obj.save()
        with pytest.raises(ValidationError, match="immutable"):
            ckpt_obj.delete()

    @override_settings(AUDIT_ANCHOR_SIGNING_KEY="v190-root-defense-secret")
    def test_detects_privileged_full_chain_rewrite_and_forged_checkpoint_signature(self) -> None:
        owner = User.objects.create_user(email="root-owner@example.com", password="Password123!")
        org = Organization.objects.create(name="Root Defense", slug="root-defense", plan="pro")
        OrganizationMember.objects.create(organization=org, user=owner, role="owner")
        owner_client = _auth_client(owner, org)

        for idx in range(1, 4):
            AuditLog.objects.create(
                organization=org,
                user=owner,
                action="created",
                resource_type="Task",
                resource_id=f"orig-{idx}",
                metadata={"amount": idx * 100},
            )

        # Anchor HMAC checkpoint #1 covering chain_seq 1..3 via Beat task
        sweep = anchor_audit_chain_checkpoints(batch_size=10)
        assert sweep["anchored"] == 1

        verify_ok = owner_client.get(f"/api/v1/organizations/{org.id}/audit-logs/verify/").json()
        assert verify_ok["valid"] is True
        assert verify_ok["checkpoint_valid"] is True
        assert verify_ok["checkpoints_verified"] == 1

        # Simulate privileged DBA rewriting ALL AuditLog rows AND recomputing every prev_hash/entry_hash!
        rows = list(AuditLog.objects.filter(organization=org).order_by("chain_seq"))
        prev_h = GENESIS_AUDIT_HASH
        for row in rows:
            row.metadata = {"amount": 0, "rewritten_by_dba": True}
            row.prev_hash = prev_h
            row.entry_hash = compute_audit_entry_hash(row)
            AuditLog.objects.filter(pk=row.pk).update(
                metadata=row.metadata,
                prev_hash=row.prev_hash,
                entry_hash=row.entry_hash,
            )
            prev_h = row.entry_hash

        # Internal AuditLog links are self-consistent, YET checkpoint #1 catches root replacement!
        verify_rewritten = owner_client.get(
            f"/api/v1/organizations/{org.id}/audit-logs/verify/"
        ).json()
        assert verify_rewritten["violations"] == []
        assert verify_rewritten["valid"] is False
        assert verify_rewritten["checkpoint_valid"] is False
        assert (
            "checkpoint_anchor_divergence"
            in verify_rewritten["checkpoint_violations"][0]["reasons"]
        )

        # Refuses to mint a new checkpoint on top of a compromised chain (409 Conflict)
        conflict = owner_client.post(
            f"/api/v1/organizations/{org.id}/audit-logs/checkpoints/",
            {"force": True},
            format="json",
        )
        assert conflict.status_code == 409

        # Attacker also alters AuditChainCheckpoint.head_hash in SQL without AUDIT_ANCHOR_SIGNING_KEY
        ckpt = AuditChainCheckpoint.objects.get(organization=org, checkpoint_seq=1)
        AuditChainCheckpoint.objects.filter(pk=ckpt.pk).update(head_hash=rows[-1].entry_hash)
        verify_forged = owner_client.get(
            f"/api/v1/organizations/{org.id}/audit-logs/verify/"
        ).json()
        assert verify_forged["valid"] is False
        assert set(verify_forged["checkpoint_violations"][0]["reasons"]) >= {
            "checkpoint_hash_mismatch",
            "checkpoint_signature_mismatch",
        }

    @override_settings(
        AUDIT_ANCHOR_SIGNING_KEY="v190-fallback-secret",
        AUDIT_WORM_S3_BUCKET="mltask-worm-unavail-bucket",
    )
    def test_s3_worm_failure_gracefully_records_anchor_error_while_preserving_hmac_seal(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
        owner = User.objects.create_user(email="s3err-owner@example.com", password="Password123!")
        org = Organization.objects.create(name="S3 Err Org", slug="s3-err-org", plan="pro")
        OrganizationMember.objects.create(organization=org, user=owner, role="owner")
        AuditLog.objects.create(
            organization=org, user=owner, action="login", resource_type="Session"
        )

        mock_conn = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status = 503
        mock_resp.read.return_value = b"<Error><Code>SlowDown</Code></Error>"
        mock_conn.getresponse.return_value = mock_resp

        owner_client = _auth_client(owner, org)
        with patch("apps.core.audit_chain.http.client.HTTPSConnection", return_value=mock_conn):
            resp = owner_client.post(
                f"/api/v1/organizations/{org.id}/audit-logs/checkpoints/",
                {},
                format="json",
            )
        assert resp.status_code == 201
        assert resp.json()["anchor_status"] == "anchor_error"
        assert "HTTP 503" in resp.json()["anchor_error"]

        verify_resp = owner_client.get(f"/api/v1/organizations/{org.id}/audit-logs/verify/")
        assert verify_resp.json()["valid"] is True
        assert verify_resp.json()["checkpoint_valid"] is True


@pytest.mark.django_db
class TestDomainLanguageSkillVectorsAndSpecialistRouting:
    """Verify multi-dimensional calibration vectors, specialist claim routing & expert gating."""

    def setup_method(self) -> None:
        cache.clear()

    def test_specialist_routing_expert_probation_guard_and_domain_weighted_consensus(self) -> None:
        owner = User.objects.create_user(email="spec-owner@example.com", password="Password123!")
        code_pro = User.objects.create_user(email="code-pro@example.com", password="Password123!")
        gen_writer_1 = User.objects.create_user(email="gen-w1@example.com", password="Password123!")
        gen_writer_2 = User.objects.create_user(email="gen-w2@example.com", password="Password123!")
        probation_u = User.objects.create_user(
            email="probation@example.com", password="Password123!"
        )
        org = Organization.objects.create(
            name="Specialist RLHF Org",
            slug="specialist-rlhf-org",
            plan="enterprise",
            max_users=50,
            max_tasks=200,
        )
        OrganizationMember.objects.create(organization=org, user=owner, role="owner")
        for member_u in (code_pro, gen_writer_1, gen_writer_2, probation_u):
            OrganizationMember.objects.create(organization=org, user=member_u, role="contributor")

        owner_client = _auth_client(owner, org)
        code_client = _auth_client(code_pro, org)
        gen1_client = _auth_client(gen_writer_1, org)
        gen2_client = _auth_client(gen_writer_2, org)
        prob_client = _auth_client(probation_u, org)

        # Create a specialized Spanish code gold task
        gold_code = owner_client.post(
            "/api/v1/tasks/",
            {
                "translations": {
                    "es": {
                        "title": "Auditar función criptográfica",
                        "description": "Comparar respuestas A y B",
                    }
                },
                "domain": "code",
                "difficulty": "hard",
                "is_gold": True,
                "gold_choice": "response_a",
            },
            format="json",
        )
        assert gold_code.status_code == 201
        gold_code_id = gold_code.json()["id"]

        # Code pro answers correctly in Spanish -> calibrates both domain='code' & language='es'
        claim_g = code_client.post("/api/v1/tasks/claim/", {}, format="json")
        assert claim_g.json()["id"] == gold_code_id
        sub_g = code_client.post(
            f"/api/v1/tasks/{gold_code_id}/annotations/",
            {"preference": "response_a", "overall_score": 5, "language": "es"},
            format="json",
        )
        assert sub_g.status_code == 201

        cal_code = AnnotatorCalibration.objects.get(organization=org, user=code_pro)
        assert cal_code.domain_skill_vectors["code"]["skill_weight"] == 1.15
        assert cal_code.language_skill_vectors["es"]["skill_weight"] == 1.15

        # Probation user fails gold task -> skill_weight = 0.45 (< 0.70 probation cutoff)
        assert (
            prob_client.post("/api/v1/tasks/claim/", {}, format="json").json()["id"] == gold_code_id
        )
        prob_client.post(
            f"/api/v1/tasks/{gold_code_id}/annotations/",
            {"preference": "response_b", "overall_score": 2, "language": "es"},
            format="json",
        )

        # Configure gen_writer_1 & gen_writer_2 with decent global weight (1.05) but poor code skill (0/4 -> 0.24)
        _, high_w = compute_bayesian_skill_weight(4, 4)
        _, low_w = compute_bayesian_skill_weight(0, 4)
        AnnotatorCalibration.objects.filter(organization=org, user=code_pro).update(
            gold_evaluated_count=4,
            gold_correct_count=4,
            accuracy_rate=1.0,
            skill_weight=high_w,
            domain_skill_vectors={
                "code": {"evaluated": 4, "correct": 4, "accuracy_rate": 1.0, "skill_weight": high_w}
            },
            language_skill_vectors={
                "es": {"evaluated": 4, "correct": 4, "accuracy_rate": 1.0, "skill_weight": high_w}
            },
        )
        for gw in (gen_writer_1, gen_writer_2):
            AnnotatorCalibration.objects.create(
                organization=org,
                user=gw,
                gold_evaluated_count=5,
                gold_correct_count=3,
                accuracy_rate=0.6,
                skill_weight=0.92,
                domain_skill_vectors={
                    "creative": {
                        "evaluated": 3,
                        "correct": 3,
                        "accuracy_rate": 1.0,
                        "skill_weight": 1.275,
                    },
                    "code": {
                        "evaluated": 4,
                        "correct": 0,
                        "accuracy_rate": 0.0,
                        "skill_weight": low_w,
                    },
                },
            )

        # Create a general task FIRST and an expert code task SECOND (same priority='high')
        gen_task = owner_client.post(
            "/api/v1/tasks/",
            {
                "title": "General Summarization Prompt",
                "domain": "general",
                "difficulty": "standard",
                "priority": "high",
            },
            format="json",
        )
        expert_code_task = owner_client.post(
            "/api/v1/tasks/",
            {
                "title": "Rust Memory-Safety Audit",
                "domain": "code",
                "difficulty": "expert",
                "priority": "high",
                "required_annotations": 3,
            },
            format="json",
        )
        assert gen_task.status_code == 201
        assert expert_code_task.status_code == 201
        gen_task_id = gen_task.json()["id"]
        expert_code_id = expert_code_task.json()["id"]

        # Filter API supports ?domain=code&difficulty=expert
        filtered = owner_client.get("/api/v1/tasks/?domain=code&difficulty=expert")
        assert filtered.status_code == 200
        assert [row["id"] for row in filtered.json()["results"]] == [expert_code_id]

        # Probation annotator requesting difficulty='expert' is gated out (204 No Content)!
        prob_expert = prob_client.post(
            "/api/v1/tasks/claim/", {"difficulty": "expert"}, format="json"
        )
        assert prob_expert.status_code == 204

        # Code specialist calling claim() without filters gets routed the 'code' task BEFORE older general task!
        spec_claim = code_client.post("/api/v1/tasks/claim/", {}, format="json")
        assert spec_claim.status_code == 200
        assert spec_claim.json()["id"] == expert_code_id
        assert spec_claim.json()["domain"] == "code"
        assert spec_claim.json()["difficulty"] == "expert"
        assert gen_task_id != expert_code_id

        # Code pro votes 'response_a' in Spanish; two non-code writers vote 'response_b'
        assert (
            code_client.post(
                f"/api/v1/tasks/{expert_code_id}/annotations/",
                {"preference": "response_a", "overall_score": 5, "language": "es"},
                format="json",
            ).status_code
            == 201
        )
        assert (
            gen1_client.post(
                f"/api/v1/tasks/{expert_code_id}/annotations/",
                {"preference": "response_b", "overall_score": 3, "language": "en"},
                format="json",
            ).status_code
            == 201
        )
        final_sub = gen2_client.post(
            f"/api/v1/tasks/{expert_code_id}/annotations/",
            {"preference": "response_b", "overall_score": 3, "language": "en"},
            format="json",
        )
        assert final_sub.status_code == 201
        consensus = final_sub.json()["consensus"]
        # Code pro effective weight = 1.36; each non-code writer = 0.70*0.24 + 0.30*0.92 = 0.444 (sum 0.888 < 1.36!)
        assert consensus["consensus_reached"] is True
        assert consensus["consensus_choice"] == "response_a"
        assert consensus["domain"] == "code"
        assert consensus["difficulty"] == "expert"

        # Specialist-filtered calibration leaderboard (?domain=code&language=es)
        lb = owner_client.get(
            f"/api/v1/organizations/{org.id}/annotators/calibration/?domain=code&language=es"
        )
        assert lb.status_code == 200
        lb_data = lb.json()
        assert lb_data["filters"] == {"domain": "code", "language": "es"}
        assert lb_data["annotators"][0]["email"] == code_pro.email
        assert "code" in lb_data["annotators"][0]["specialist_domains"]


def test_terraform_v190_worm_autoscaling_and_canary_guardrails() -> None:
    """Verify v1.9.0 S3 Object Lock WORM, ALB/Celery autoscaling, and ECS canary rollback HCL."""
    tf_dir = Path(settings.BASE_DIR) / "terraform"
    main_tf = (tf_dir / "main.tf").read_text(encoding="utf-8")
    vars_tf = (tf_dir / "variables.tf").read_text(encoding="utf-8")
    outputs_tf = (tf_dir / "outputs.tf").read_text(encoding="utf-8")

    assert 'default     = "v1.10.0"' in vars_tf
    assert 'resource "aws_s3_bucket" "audit_worm"' in main_tf
    assert "object_lock_enabled = true" in main_tf
    assert 'resource "aws_s3_bucket_object_lock_configuration" "audit_worm"' in main_tf
    assert 'mode = "COMPLIANCE"' in main_tf
    assert '{ name = "AUDIT_WORM_S3_BUCKET", value = local.audit_worm_bucket_name }' in main_tf
    assert "deployment_circuit_breaker {" in main_tf
    assert "alarm_names = local.canary_rollback_alarms" in main_tf
    assert 'resource "aws_appautoscaling_policy" "alb_requests"' in main_tf
    assert 'predefined_metric_type = "ALBRequestCountPerTarget"' in main_tf
    assert 'resource "aws_appautoscaling_target" "celery_worker"' in main_tf
    assert 'resource "aws_appautoscaling_policy" "celery_cpu"' in main_tf
    assert 'resource "aws_cloudwatch_composite_alarm" "canary_rollout_guard"' in main_tf
    assert 'output "audit_worm_bucket_name"' in outputs_tf
    assert 'output "canary_composite_alarm_arn"' in outputs_tf
