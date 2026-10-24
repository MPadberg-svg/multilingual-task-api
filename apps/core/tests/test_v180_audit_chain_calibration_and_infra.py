"""Comprehensive v1.8.0 test suite covering:
1. Cryptographic SHA-256 AuditLog hash-chaining, immutability, and tamper verification.
2. Blind Gold-Task calibration injection, Redis cache partitioning, and Bayesian skill-weighted IAA.
3. Outbox dead-letter CloudWatch log/Prometheus telemetry and Terraform RDS replica + alarms HCL.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.exceptions import ValidationError

import pytest
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.core.audit_chain import GENESIS_AUDIT_HASH, compute_audit_entry_hash
from apps.core.models import (
    AuditLog,
    Organization,
    OrganizationMember,
    OutboxEvent,
    WebhookEndpoint,
)
from apps.core.outbox import MAX_OUTBOX_ATTEMPTS, drain_outbox_batch
from apps.tasks.calibration import compute_bayesian_skill_weight
from apps.tasks.models import AnnotatorCalibration, Task

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
class TestCryptographicAuditHashChain:
    """Verify SHA-256 audit hash-chaining, immutability guards, and tamper verification API."""

    def test_audit_chain_monotonicity_immutability_and_tenant_isolation(self) -> None:
        owner = User.objects.create_user(email="chain-owner@example.com", password="Password123!")
        org_a = Organization.objects.create(name="Chain Org A", slug="chain-org-a", plan="pro")
        org_b = Organization.objects.create(name="Chain Org B", slug="chain-org-b", plan="pro")
        OrganizationMember.objects.create(organization=org_a, user=owner, role="owner")
        OrganizationMember.objects.create(organization=org_b, user=owner, role="owner")

        e1 = AuditLog.objects.create(
            organization=org_a,
            user=owner,
            action="login",
            resource_type="Session",
            resource_id="s1",
            ip_address="198.51.100.10",
            metadata={"step": 1},
        )
        e2 = AuditLog.objects.create(
            organization=org_a,
            user=owner,
            action="created",
            resource_type="Task",
            resource_id="t1",
            ip_address="198.51.100.10",
            metadata={"step": 2},
        )
        b1 = AuditLog.objects.create(
            organization=org_b,
            user=owner,
            action="login",
            resource_type="Session",
            resource_id="sb1",
        )
        g1 = AuditLog.objects.create(
            organization=None,
            user=owner,
            action="login",
            resource_type="GlobalSession",
        )

        assert e1.chain_seq == 1
        assert e1.prev_hash == GENESIS_AUDIT_HASH
        assert len(e1.entry_hash) == 64
        assert e1.entry_hash == compute_audit_entry_hash(e1)

        assert e2.chain_seq == 2
        assert e2.prev_hash == e1.entry_hash
        assert e2.entry_hash == compute_audit_entry_hash(e2)

        assert b1.chain_seq == 1
        assert b1.prev_hash == GENESIS_AUDIT_HASH
        assert g1.chain_seq == 1
        assert g1.prev_hash == GENESIS_AUDIT_HASH

        e1.action = "deleted"
        with pytest.raises(ValidationError, match="immutable"):
            e1.save()
        with pytest.raises(ValidationError, match="immutable"):
            e1.delete()

    def test_verify_endpoint_rbac_replica_header_and_tamper_detection(self) -> None:
        owner = User.objects.create_user(email="ver-owner@example.com", password="Password123!")
        contrib = User.objects.create_user(email="ver-contrib@example.com", password="Password123!")
        outsider = User.objects.create_user(email="ver-out@example.com", password="Password123!")
        org = Organization.objects.create(name="Verify Org", slug="verify-org", plan="enterprise")
        OrganizationMember.objects.create(organization=org, user=owner, role="owner")
        OrganizationMember.objects.create(organization=org, user=contrib, role="contributor")

        entries = [
            AuditLog.objects.create(
                organization=org,
                user=owner,
                action="created",
                resource_type="Task",
                resource_id=f"task-{idx}",
                metadata={"idx": idx},
            )
            for idx in range(1, 5)
        ]

        contrib_client = _auth_client(contrib, org)
        assert (
            contrib_client.get(f"/api/v1/organizations/{org.id}/audit-logs/verify/").status_code
            == 403
        )
        outsider_client = _auth_client(outsider)
        assert (
            outsider_client.get(f"/api/v1/organizations/{org.id}/audit-logs/verify/").status_code
            == 404
        )

        owner_client = _auth_client(owner, org)
        ok_resp = owner_client.get(f"/api/v1/organizations/{org.id}/audit-logs/verify/")
        assert ok_resp.status_code == 200
        assert ok_resp.headers["X-Query-Target"] == "primary"
        body = ok_resp.json()
        assert body["valid"] is True
        assert body["verified_entries"] == 4
        assert body["head_hash"] == entries[-1].entry_hash
        assert body["violations"] == []
        assert len(body["manifest_digest"]) == 64

        list_resp = owner_client.get(f"/api/v1/organizations/{org.id}/audit-logs/")
        assert list_resp.status_code == 200
        assert list_resp.headers["X-Query-Target"] == "primary"
        assert [row["chain_seq"] for row in list_resp.json()["results"]] == [4, 3, 2, 1]

        # Simulate direct DB payload tampering bypassing ORM save()
        AuditLog.objects.filter(pk=entries[1].pk).update(metadata={"idx": 999, "tampered": True})
        tampered_resp = owner_client.get(f"/api/v1/organizations/{org.id}/audit-logs/verify/")
        assert tampered_resp.status_code == 200
        tampered = tampered_resp.json()
        assert tampered["valid"] is False
        assert tampered["first_corrupted_seq"] == 2
        assert tampered["first_corrupted_id"] == str(entries[1].id)
        assert "entry_hash_mismatch" in tampered["violations"][0]["reasons"]

        # Simulate DBA row deletion leaving a sequence gap + broken prev_hash link
        AuditLog.objects.filter(pk=entries[1].pk).delete()
        gap_resp = owner_client.get(f"/api/v1/organizations/{org.id}/audit-logs/verify/")
        gap = gap_resp.json()
        assert gap["valid"] is False
        assert gap["first_corrupted_seq"] == 3
        assert set(gap["violations"][0]["reasons"]) >= {"sequence_gap", "prev_hash_mismatch"}


@pytest.mark.django_db
class TestGoldCalibrationAndSkillWeightedConsensus:
    """Verify blind gold-task injection, cache isolation, leaderboard, and Bayesian consensus."""

    def setup_method(self) -> None:
        cache.clear()

    def test_gold_task_rbac_validation_and_redis_cache_blindness(self) -> None:
        admin_u = User.objects.create_user(email="gold-admin@example.com", password="Password123!")
        worker_u = User.objects.create_user(email="gold-work@example.com", password="Password123!")
        org = Organization.objects.create(
            name="Gold Cache Org", slug="gold-cache-org", plan="enterprise", max_users=20
        )
        OrganizationMember.objects.create(organization=org, user=admin_u, role="admin")
        OrganizationMember.objects.create(organization=org, user=worker_u, role="contributor")

        admin_client = _auth_client(admin_u, org)
        worker_client = _auth_client(worker_u, org)

        # Contributor cannot create gold calibration tasks
        denied = worker_client.post(
            "/api/v1/tasks/",
            {"title": "Sneaky Gold", "is_gold": True, "gold_choice": "a"},
            format="json",
        )
        assert denied.status_code == 403

        # Validation: is_gold=True requires gold_choice, and gold_choice requires is_gold=True
        bad_missing = admin_client.post(
            "/api/v1/tasks/",
            {"title": "Missing Choice", "is_gold": True},
            format="json",
        )
        assert bad_missing.status_code == 400
        bad_flag = admin_client.post(
            "/api/v1/tasks/",
            {"title": "Missing Flag", "is_gold": False, "gold_choice": "b"},
            format="json",
        )
        assert bad_flag.status_code == 400

        # Admin creates a valid gold calibration task (warming admin view first!)
        created = admin_client.post(
            "/api/v1/tasks/",
            {"title": "Reference Gold Prompt", "is_gold": True, "gold_choice": "a"},
            format="json",
        )
        assert created.status_code == 201
        task_id = created.json()["id"]
        assert created.json()["is_gold"] is True
        assert created.json()["gold_choice"] == "response_a"

        # Admin hits GET list & retrieve first -> populates Redis cache
        adm_list = admin_client.get("/api/v1/tasks/")
        adm_detail = admin_client.get(f"/api/v1/tasks/{task_id}/")
        assert adm_list.status_code == 200
        assert adm_list.json()["results"][0]["gold_choice"] == "response_a"
        assert adm_detail.json()["is_gold"] is True

        # Contributor immediately hits GET list & retrieve -> MUST NOT leak gold metadata!
        wrk_list = worker_client.get("/api/v1/tasks/")
        wrk_detail = worker_client.get(f"/api/v1/tasks/{task_id}/")
        assert wrk_list.status_code == 200
        assert "is_gold" not in wrk_list.json()["results"][0]
        assert "gold_choice" not in wrk_list.json()["results"][0]
        assert "is_gold" not in wrk_detail.json()
        assert "gold_choice" not in wrk_detail.json()

        # Export excludes gold calibration tasks by default; admin may opt-in via include_gold=true
        assert worker_client.get("/api/v1/tasks/export/?export_format=json").json() == []
        assert (
            worker_client.get("/api/v1/tasks/export/?export_format=json&include_gold=true").json()
            == []
        )
        assert admin_client.get("/api/v1/tasks/export/?export_format=json").json() == []
        assert (
            len(
                admin_client.get(
                    "/api/v1/tasks/export/?export_format=json&include_gold=true"
                ).json()
            )
            == 1
        )

    def test_blind_gold_injection_reusability_and_skill_weighted_consensus(self) -> None:
        owner = User.objects.create_user(email="cal-owner@example.com", password="Password123!")
        expert = User.objects.create_user(email="cal-expert@example.com", password="Password123!")
        spammer_1 = User.objects.create_user(email="cal-spam1@example.com", password="Password123!")
        spammer_2 = User.objects.create_user(email="cal-spam2@example.com", password="Password123!")
        org = Organization.objects.create(
            name="RLHF Calibration Lab",
            slug="rlhf-calibration-lab",
            plan="enterprise",
            max_users=50,
            max_tasks=200,
        )
        OrganizationMember.objects.create(organization=org, user=owner, role="owner")
        for u in (expert, spammer_1, spammer_2):
            OrganizationMember.objects.create(organization=org, user=u, role="contributor")

        owner_client = _auth_client(owner, org)
        expert_client = _auth_client(expert, org)
        spam1_client = _auth_client(spammer_1, org)
        spam2_client = _auth_client(spammer_2, org)

        # Create regular production task FIRST, and gold calibration task SECOND
        reg_resp = owner_client.post(
            "/api/v1/tasks/",
            {
                "title": "Production RLHF Comparison",
                "priority": "high",
                "required_annotations": 3,
            },
            format="json",
        )
        assert reg_resp.status_code == 201
        prod_task_id = reg_resp.json()["id"]

        gold_resp = owner_client.post(
            "/api/v1/tasks/",
            {
                "title": "Hidden Calibration Check #1",
                "priority": "medium",
                "is_gold": True,
                "gold_choice": "response_a",
            },
            format="json",
        )
        assert gold_resp.status_code == 201
        gold_task_id = gold_resp.json()["id"]

        # Uncalibrated expert claims -> receives blind gold task BEFORE higher-priority prod task!
        exp_claim_1 = expert_client.post("/api/v1/tasks/claim/", {}, format="json")
        assert exp_claim_1.status_code == 200
        assert exp_claim_1.json()["id"] == gold_task_id
        assert "is_gold" not in exp_claim_1.json()
        assert "gold_choice" not in exp_claim_1.json()

        # Expert answers gold task correctly -> lease released, response stays blind
        exp_sub_gold = expert_client.post(
            f"/api/v1/tasks/{gold_task_id}/annotations/",
            {"preference": "response_a", "overall_score": 5, "rationale": "Clear factual winner."},
            format="json",
        )
        assert exp_sub_gold.status_code == 201
        assert "is_correct" not in exp_sub_gold.json()["consensus"]
        assert OutboxEvent.objects.filter(
            organization=org, event_type="annotator.calibrated"
        ).exists()

        gold_refreshed = Task.objects.get(pk=gold_task_id)
        assert gold_refreshed.claimed_by_id is None
        assert gold_refreshed.status == "pending"

        # Spammer 1 (also uncalibrated) claims -> receives the SAME reusable gold task and fails it!
        s1_claim_gold = spam1_client.post("/api/v1/tasks/claim/", {}, format="json")
        assert s1_claim_gold.status_code == 200
        assert s1_claim_gold.json()["id"] == gold_task_id
        s1_sub_gold = spam1_client.post(
            f"/api/v1/tasks/{gold_task_id}/annotations/",
            {"preference": "response_b", "overall_score": 1},
            format="json",
        )
        assert s1_sub_gold.status_code == 201

        # Spammer 2 also fails gold task + calibrate further (4/4 for expert vs 0/4 for spammers)
        s2_claim_gold = spam2_client.post("/api/v1/tasks/claim/", {}, format="json")
        assert s2_claim_gold.json()["id"] == gold_task_id
        spam2_client.post(
            f"/api/v1/tasks/{gold_task_id}/annotations/",
            {"preference": "response_b", "overall_score": 1},
            format="json",
        )

        # Advance calibration counts to 4 evaluated gold tasks to test multi-gold Bayesian separation
        exp_acc, exp_w = compute_bayesian_skill_weight(4, 4)
        spm_acc, spm_w = compute_bayesian_skill_weight(0, 4)
        assert exp_w == 1.36
        assert spm_w == 0.24
        AnnotatorCalibration.objects.filter(organization=org, user=expert).update(
            gold_evaluated_count=4,
            gold_correct_count=4,
            accuracy_rate=exp_acc,
            skill_weight=exp_w,
        )
        AnnotatorCalibration.objects.filter(
            organization=org, user__in=[spammer_1, spammer_2]
        ).update(
            gold_evaluated_count=4,
            gold_correct_count=0,
            accuracy_rate=spm_acc,
            skill_weight=spm_w,
        )

        # Expert's next claim skips already-answered gold task and claims prod_task_id!
        exp_claim_prod = expert_client.post("/api/v1/tasks/claim/", {}, format="json")
        assert exp_claim_prod.status_code == 200
        assert exp_claim_prod.json()["id"] == prod_task_id

        # 1 Expert votes 'response_a' (weight 1.36); 2 Spammers vote 'response_b' (0.24 + 0.24 = 0.48)
        assert (
            expert_client.post(
                f"/api/v1/tasks/{prod_task_id}/annotations/",
                {"preference": "response_a", "overall_score": 5},
                format="json",
            ).status_code
            == 201
        )
        assert (
            spam1_client.post(
                f"/api/v1/tasks/{prod_task_id}/annotations/",
                {"preference": "response_b", "overall_score": 2},
                format="json",
            ).status_code
            == 201
        )
        final_sub = spam2_client.post(
            f"/api/v1/tasks/{prod_task_id}/annotations/",
            {"preference": "response_b", "overall_score": 2},
            format="json",
        )
        assert final_sub.status_code == 201
        consensus = final_sub.json()["consensus"]
        assert consensus["skill_weighted"] is True
        assert consensus["consensus_reached"] is True
        assert consensus["consensus_choice"] == "response_a"
        assert consensus["consensus_score"] == round(1.36 / (1.36 + 0.24 + 0.24), 4)
        assert consensus["unweighted_agreement_score"] == round(2 / 3, 4)

        # Admin calibration leaderboard endpoint
        assert (
            expert_client.get(f"/api/v1/organizations/{org.id}/annotators/calibration/").status_code
            == 403
        )
        lb_resp = owner_client.get(f"/api/v1/organizations/{org.id}/annotators/calibration/")
        assert lb_resp.status_code == 200
        assert lb_resp.headers["X-Query-Target"] == "primary"
        lb = lb_resp.json()
        assert lb["gold_task_count"] == 1
        assert lb["calibrated_annotators"] == 3
        assert lb["annotators"][0]["email"] == expert.email
        assert lb["annotators"][0]["status"] == "trusted"
        assert lb["annotators"][-1]["status"] == "probation"

        # Hash chain across the entire RLHF + gold calibration workflow remains 100% valid
        verify_resp = owner_client.get(f"/api/v1/organizations/{org.id}/audit-logs/verify/")
        assert verify_resp.json()["valid"] is True
        assert verify_resp.json()["verified_entries"] >= 6


@pytest.mark.django_db
class TestOutboxDeadLetterObservabilityAndTerraformIaC:
    """Verify Outbox DLQ structured logs, Prometheus gauges, and Terraform v1.8.0 HCL alignment."""

    def test_outbox_dead_letter_log_and_prometheus_metrics(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        org = Organization.objects.create(name="DLQ Org", slug="dlq-org")
        WebhookEndpoint.objects.create(
            organization=org,
            url="https://hooks.example.org/receiver",
            events=["task.created"],
            is_active=True,
        )
        ev = OutboxEvent.objects.create(
            organization=org,
            topic="webhook",
            event_type="task.created",
            payload={"event": "task.created", "data": {"task_id": "1"}},
            attempts=MAX_OUTBOX_ATTEMPTS - 1,
        )

        with caplog.at_level(logging.ERROR, logger="apps.core.outbox"):
            with patch(
                "apps.core.outbox.dispatch_organization_webhooks",
                side_effect=RuntimeError("upstream 502 bad gateway"),
            ):
                stats = drain_outbox_batch(batch_size=10)

        assert stats["failed"] == 1
        ev.refresh_from_db()
        assert ev.status == "failed"
        assert any("Outbox event moved to dead-letter" in rec.message for rec in caplog.records)

        client = APIClient()
        with patch.object(settings, "METRICS_AUTH_TOKEN", "test-metrics-secret", create=True):
            m_resp = client.get(
                "/api/v1/metrics/",
                HTTP_AUTHORIZATION="Bearer test-metrics-secret",
            )
        assert m_resp.status_code == 200
        body = m_resp.content.decode("utf-8")
        assert "mltask_outbox_dead_letter_events 1" in body
        assert "mltask_outbox_pending_events 0" in body

    def test_terraform_rds_replica_alarms_and_strict_hcl_formatting(self) -> None:
        tf_dir = Path(settings.BASE_DIR) / "terraform"
        main_tf = (tf_dir / "main.tf").read_text(encoding="utf-8")
        vars_tf = (tf_dir / "variables.tf").read_text(encoding="utf-8")
        outputs_tf = (tf_dir / "outputs.tf").read_text(encoding="utf-8")

        assert 'resource "aws_db_instance" "postgres_replica"' in main_tf
        assert "replicate_source_db = aws_db_instance.postgres.identifier" in main_tf
        assert '{ name = "POSTGRES_REPLICA_HOST", value = local.postgres_replica_host }' in main_tf
        assert 'resource "aws_cloudwatch_log_metric_filter" "outbox_dead_letter"' in main_tf
        assert 'resource "aws_cloudwatch_metric_alarm" "outbox_dead_letter"' in main_tf
        assert 'resource "aws_cloudwatch_metric_alarm" "rds_replica_lag"' in main_tf
        assert 'resource "aws_cloudwatch_metric_alarm" "rds_primary_cpu"' in main_tf
        assert 'resource "aws_cloudwatch_metric_alarm" "alb_target_5xx"' in main_tf
        assert 'output "rds_replica_endpoint"' in outputs_tf
        assert 'default     = "v1.' in vars_tf

        # Extract aws_db_instance.postgres_replica block and verify AWS ~> 5.0 replica constraints
        replica_match = re.search(
            r'resource "aws_db_instance" "postgres_replica" \{(.*?)\n\}',
            main_tf,
            re.DOTALL,
        )
        assert replica_match is not None
        replica_body = replica_match.group(1)
        for forbidden_attr in (
            "engine ",
            "engine=",
            "db_name",
            "username",
            "password",
            "allocated_storage",
            "db_subnet_group_name",
        ):
            assert forbidden_attr not in replica_body

        # Verify strict 2-space indentation, no tabs, no trailing spaces, and '=' group alignment
        assign_re = re.compile(r"^( +)([A-Za-z0-9_-]+)( +)= ")
        for tf_file in sorted(tf_dir.glob("*.tf")) + [tf_dir / "terraform.tfvars.example"]:
            raw = tf_file.read_text(encoding="utf-8")
            assert raw.endswith("\n"), f"{tf_file.name} missing trailing newline"
            group: list[tuple[int, int, str, int, int]] = []

            def _flush_group(items: list[tuple[int, int, str, int, int]], fname: str) -> None:
                if len(items) > 1:
                    expected_eq_col = items[0][1] + max(it[3] for it in items) + 1
                    for g_line, _ind, g_key, _klen, g_eq in items:
                        assert g_eq == expected_eq_col, (
                            f"Misaligned '=' in {fname}:{g_line} ({g_key}): "
                            f"got col {g_eq}, expected {expected_eq_col}"
                        )

            for lineno, line in enumerate(raw.splitlines(), start=1):
                assert "\t" not in line, f"Tab character in {tf_file.name}:{lineno}"
                assert line == line.rstrip(" "), f"Trailing space in {tf_file.name}:{lineno}"
                m = assign_re.match(line)
                if m and not line.rstrip().endswith(("{", "[", "(")):
                    indent_len = len(m.group(1))
                    assert indent_len % 2 == 0, f"Odd indentation in {tf_file.name}:{lineno}"
                    key_name = m.group(2)
                    eq_col = indent_len + len(key_name) + len(m.group(3))
                    if group and group[-1][1] != indent_len:
                        _flush_group(group, tf_file.name)
                        group.clear()
                    group.append((lineno, indent_len, key_name, len(key_name), eq_col))
                else:
                    _flush_group(group, tf_file.name)
                    group.clear()
            _flush_group(group, tf_file.name)
