"""Comprehensive v1.11.0 test suite covering:
1. RFC 9162 §2.1 binary Merkle transparency trees, O(log N) single-event inclusion proofs,
   append-only checkpoint consistency proofs, and zero-secret offline proof verification.
2. Streaming DPO / RLHF dataset export pipeline (/api/v1/tasks/export-dpo/) with quality gates,
   regex PII scrubbing, deterministic train/eval splits, M2M tasks:export scope checks,
   Ed25519-signed provenance manifests, and SigV4 S3 snapshot archival.
3. Adaptive per-(organization, domain) active-learning uncertainty thresholds
   (DomainUncertaintyPolicy, online/Beat empirical calibration, and /uncertainty-policies/).
4. Terraform v1.11.0 encrypted S3 dataset export archive bucket & lifecycle IaC.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import override_settings

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.core.audit_chain import verify_audit_inclusion_bundle_offline
from apps.core.merkle import (
    EMPTY_MERKLE_ROOT,
    build_merkle_consistency_proof,
    build_merkle_inclusion_proof,
    compute_merkle_root,
    hash_merkle_children,
    hash_merkle_leaf,
    verify_merkle_consistency_proof,
    verify_merkle_inclusion_path,
)
from apps.core.models import (
    AuditChainCheckpoint,
    AuditLog,
    Organization,
    OrganizationAPIKey,
    OrganizationMember,
    OutboxEvent,
)
from apps.tasks.calibration import compute_bayesian_skill_weight
from apps.tasks.dpo_export import scrub_dataset_pii, verify_dpo_manifest_offline
from apps.tasks.models import AnnotatorCalibration, DomainUncertaintyPolicy, Task, TaskAnnotation
from apps.tasks.tasks import calibrate_adaptive_uncertainty_thresholds

User = get_user_model()


def _auth_client(user: Any, org: Organization | None = None) -> APIClient:
    client = APIClient()
    token = str(RefreshToken.for_user(user).access_token)
    creds: dict[str, str] = {"HTTP_AUTHORIZATION": f"Bearer {token}"}
    if org is not None:
        creds["HTTP_X_ORGANIZATION_ID"] = str(org.id)
    client.credentials(**creds)
    return client


def _ed25519_keypair_pems() -> tuple[str, str]:
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    pub_pem = (
        priv.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    return priv_pem, pub_pem


def _mock_openai_completion(payload: dict[str, Any]) -> MagicMock:
    msg = MagicMock()
    msg.content = json.dumps(payload)
    choice = MagicMock()
    choice.message = msg
    usage = MagicMock()
    usage.prompt_tokens = 110
    usage.completion_tokens = 45
    usage.total_tokens = 155
    resp = MagicMock()
    resp.choices = [choice]
    resp.usage = usage
    return resp


class TestRFC9162MerkleTransparencyAndProofs:
    """Verify RFC 9162 Merkle trees, O(log N) inclusion proofs & consistency proofs."""

    def test_rfc9162_domain_separation_and_proof_invariants(self) -> None:
        assert compute_merkle_root([]) == EMPTY_MERKLE_ROOT
        leaves = [hashlib.sha256(f"event-{i}".encode("utf-8")).hexdigest() for i in range(11)]
        # Leaf (0x00) and interior node (0x01) prefixes prevent second-preimage collisions
        assert hash_merkle_leaf(leaves[0]) != hash_merkle_children(leaves[0], leaves[1])

        root_11 = compute_merkle_root(leaves)
        for idx in range(11):
            path = build_merkle_inclusion_proof(leaves, idx)
            assert len(path) <= 4  # ceil(log2(11)) == 4
            verified = verify_merkle_inclusion_path(
                leaf_hex=leaves[idx],
                leaf_index=idx,
                tree_size=11,
                audit_path=path,
                expected_root=root_11,
            )
            assert verified["valid"] is True

        # Consistency proof from prefix size 5 -> 11 and power-of-two size 4 -> 11
        for first_n in (4, 5):
            first_root = compute_merkle_root(leaves[:first_n])
            cpath = build_merkle_consistency_proof(leaves, first_n)
            cres = verify_merkle_consistency_proof(
                first_size=first_n,
                second_size=11,
                first_root=first_root,
                second_root=root_11,
                consistency_path=cpath,
            )
            assert cres["valid"] is True
            # Equivocated root fails consistency verification immediately
            bad_cres = verify_merkle_consistency_proof(
                first_size=first_n,
                second_size=11,
                first_root=hashlib.sha256(b"equivocated").hexdigest(),
                second_root=root_11,
                consistency_path=cpath,
            )
            assert bad_cres["valid"] is False
            assert set(bad_cres["reasons"]) & {"first_root_mismatch", "second_root_mismatch"}

        # Verify empty/equal/out-of-bounds Merkle consistency & inclusion edge cases
        assert (
            verify_merkle_consistency_proof(
                first_size=0,
                second_size=11,
                first_root=EMPTY_MERKLE_ROOT,
                second_root=root_11,
                consistency_path=[],
            )["valid"]
            is True
        )
        assert (
            verify_merkle_consistency_proof(
                first_size=11,
                second_size=11,
                first_root=root_11,
                second_root=root_11,
                consistency_path=[],
            )["valid"]
            is True
        )
        assert (
            verify_merkle_consistency_proof(
                first_size=12,
                second_size=11,
                first_root=root_11,
                second_root=root_11,
                consistency_path=[],
            )["valid"]
            is False
        )
        assert (
            verify_merkle_inclusion_path(
                leaf_hex=leaves[0],
                leaf_index=99,
                tree_size=11,
                audit_path=[],
                expected_root=root_11,
            )["valid"]
            is False
        )
        assert (
            verify_merkle_inclusion_path(
                leaf_hex="not-a-hex",
                leaf_index=0,
                tree_size=11,
                audit_path=[],
                expected_root=root_11,
            )["valid"]
            is False
        )

    @pytest.mark.django_db
    def test_inclusion_and_consistency_endpoints_and_merkle_tamper_detection(self) -> None:
        cache.clear()
        owner = User.objects.create_user(email="merkle-owner@example.com", password="Password123!")
        contrib = User.objects.create_user(
            email="merkle-contrib@example.com", password="Password123!"
        )
        outsider = User.objects.create_user(
            email="merkle-outsider@example.com", password="Password123!"
        )
        org = Organization.objects.create(
            name="Merkle Transparency Org",
            slug="merkle-transparency-org",
            plan="enterprise",
        )
        OrganizationMember.objects.create(organization=org, user=owner, role="owner")
        OrganizationMember.objects.create(organization=org, user=contrib, role="contributor")

        owner_client = _auth_client(owner, org)
        contrib_client = _auth_client(contrib, org)
        outsider_client = _auth_client(outsider)
        ed_priv_pem, ed_pub_pem = _ed25519_keypair_pems()

        entries = [
            AuditLog.objects.create(
                organization=org,
                user=owner,
                action="created",
                resource_type="Task",
                resource_id=f"task-{idx}",
                metadata={"idx": idx},
            )
            for idx in range(5)
        ]

        # Before checkpointing -> 409 Conflict (entry_not_yet_checkpointed)
        unanchored = owner_client.get(
            f"/api/v1/organizations/{org.id}/audit-logs/{entries[2].id}/inclusion-proof/"
        )
        assert unanchored.status_code == 409
        assert unanchored.json()["code"] == "entry_not_yet_checkpointed"

        # RBAC: non-member -> 404, non-admin contributor -> 403
        assert (
            outsider_client.get(
                f"/api/v1/organizations/{org.id}/audit-logs/{entries[2].id}/inclusion-proof/"
            ).status_code
            == 404
        )
        assert (
            contrib_client.get(
                f"/api/v1/organizations/{org.id}/audit-logs/{entries[2].id}/inclusion-proof/"
            ).status_code
            == 403
        )

        with override_settings(AUDIT_ANCHOR_ED25519_PRIVATE_KEY_PEM=ed_priv_pem):
            ckpt_1_resp = owner_client.post(
                f"/api/v1/organizations/{org.id}/audit-logs/checkpoints/",
                {},
                format="json",
            )
            assert ckpt_1_resp.status_code == 201
            ckpt_1 = ckpt_1_resp.json()
            assert len(ckpt_1["merkle_root"]) == 64

            # Append 4 more entries and mint checkpoint #2
            more_entries = [
                AuditLog.objects.create(
                    organization=org,
                    user=owner,
                    action="updated",
                    resource_type="Task",
                    resource_id=f"task-{idx}",
                    metadata={"idx": idx},
                )
                for idx in range(5, 9)
            ]
            ckpt_2_resp = owner_client.post(
                f"/api/v1/organizations/{org.id}/audit-logs/checkpoints/",
                {},
                format="json",
            )
            assert ckpt_2_resp.status_code == 201

            # O(log N) inclusion proof for entry #3 against latest checkpoint
            proof_resp = owner_client.get(
                f"/api/v1/organizations/{org.id}/audit-logs/{entries[2].id}/inclusion-proof/"
            )
            assert proof_resp.status_code == 200
            bundle = proof_resp.json()
            assert bundle["proof_spec"] == "RFC9162-SHA256"
            assert bundle["inclusion_proof"]["leaf_index"] == 2
            assert bundle["inclusion_proof"]["path_length"] <= 4
            assert bundle["offline_verification"]["valid"] is True

            # Pure offline zero-secret verification succeeds with public key alone
            offline_ok = verify_audit_inclusion_bundle_offline(bundle, ed_pub_pem)
            assert offline_ok["valid"] is True

            # Tampering metadata in offline bundle breaks entry_hash & Merkle path
            tampered_bundle = json.loads(json.dumps(bundle))
            tampered_bundle["entry"]["metadata"]["idx"] = 9999
            offline_bad = verify_audit_inclusion_bundle_offline(tampered_bundle, ed_pub_pem)
            assert offline_bad["valid"] is False
            assert "entry_hash_mismatch" in offline_bad["reasons"]

            # Requesting inclusion of newer entry against older checkpoint #1 -> 409
            precedes = owner_client.get(
                f"/api/v1/organizations/{org.id}/audit-logs/{more_entries[-1].id}/inclusion-proof/"
                f"?checkpoint_id={ckpt_1['id']}"
            )
            assert precedes.status_code == 409
            assert precedes.json()["code"] == "checkpoint_precedes_entry"

            # Consistency proof across checkpoint #1 -> checkpoint #2
            cons_resp = owner_client.get(
                f"/api/v1/organizations/{org.id}/audit-logs/checkpoints/consistency-proof/"
                "?from_seq=1&to_seq=2"
            )
            assert cons_resp.status_code == 200
            cons_body = cons_resp.json()
            assert cons_body["verification"]["valid"] is True
            assert cons_body["first_tree_size"] < cons_body["second_tree_size"]

            # Corrupting merkle_root directly in DB triggers checkpoint_merkle_root_mismatch
            AuditChainCheckpoint.objects.filter(id=ckpt_1["id"]).update(merkle_root="f" * 64)
            verify_resp = owner_client.get(
                f"/api/v1/organizations/{org.id}/audit-logs/verify/"
            ).json()
            assert verify_resp["valid"] is False
            reasons = verify_resp["checkpoint_violations"][0]["reasons"]
            assert "checkpoint_merkle_root_mismatch" in reasons
            assert "checkpoint_hash_mismatch" in reasons


@pytest.mark.django_db
class TestDPODatasetExportPipelineAndProvenance:
    """Verify /api/v1/tasks/export-dpo/ quality gates, PII redaction, splits, M2M & S3 archive."""

    def setup_method(self) -> None:
        cache.clear()

    def test_dpo_export_quality_gates_pii_scrubbing_splits_manifest_and_s3_archive(self) -> None:
        owner = User.objects.create_user(email="dpo-owner@example.com", password="Password123!")
        contrib = User.objects.create_user(email="dpo-contrib@example.com", password="Password123!")
        ann_expert = User.objects.create_user(
            email="dpo-expert@example.com", password="Password123!"
        )
        org = Organization.objects.create(
            name="DPO Pipeline Org",
            slug="dpo-pipeline-org",
            plan="enterprise",
            max_users=25,
            max_tasks=100,
        )
        OrganizationMember.objects.create(organization=org, user=owner, role="owner")
        OrganizationMember.objects.create(organization=org, user=contrib, role="contributor")
        OrganizationMember.objects.create(organization=org, user=ann_expert, role="contributor")

        _, high_w = compute_bayesian_skill_weight(5, 5)
        AnnotatorCalibration.objects.create(
            organization=org,
            user=ann_expert,
            gold_evaluated_count=5,
            gold_correct_count=5,
            accuracy_rate=1.0,
            skill_weight=high_w,
            domain_skill_vectors={"code": {"correct": 5, "total": 5, "weight": high_w}},
        )

        # Create 6 consensus-verified tasks (1 containing PII & secrets), 1 unresolved task, 1 gold task
        exported_ids: list[str] = []
        for idx in range(6):
            t = Task.objects.create(
                user=owner,
                organization=org,
                status="completed",
                priority="high",
                domain="code" if idx % 2 == 0 else "math",
                difficulty="expert" if idx == 0 else "standard",
                consensus_choice="response_a" if idx % 2 == 0 else "response_b",
                consensus_score=0.92,
                uncertainty_score=0.24,
                judge_uncertainty_score=0.29,
                required_annotations=1,
            )
            t.set_current_language("en")
            if idx == 0:
                t.title = "Debug webhook auth for ops@acme.io from 192.168.1.44"
                t.description = (
                    "Rotate key sk-abcdefghijklmnopqrstuvwxyz123456 and call +1 415-555-0199."
                )
            else:
                t.title = f"Verified Preference Prompt #{idx}"
                t.description = f"Compare candidate implementations for case #{idx}."
            t.save()
            TaskAnnotation.objects.create(
                task=t,
                annotator=ann_expert,
                preference=t.consensus_choice,
                response_a=(
                    f"Implementation A for #{idx} (SSN 123-45-6789)"
                    if idx == 0
                    else f"Clean solution A-{idx}"
                ),
                response_b=f"Suboptimal solution B-{idx}",
                rubric_scores={"overall": 5, "helpfulness": 5, "harmlessness": 5, "honesty": 5},
                rationale="Reviewed by expert@acme.io",
            )
            exported_ids.append(str(t.id))

        # Unresolved task -> excluded by quality gate
        unresolved = Task.objects.create(
            user=owner,
            organization=org,
            status="in_progress",
            consensus_choice="",
        )
        unresolved.set_current_language("en")
        unresolved.title = "Unresolved Draft"
        unresolved.save()

        # Gold trap task -> excluded unless admin passes ?include_gold=true
        gold_task = Task.objects.create(
            user=owner,
            organization=org,
            status="completed",
            is_gold=True,
            gold_choice="response_a",
            consensus_choice="response_a",
            consensus_score=1.0,
        )
        gold_task.set_current_language("en")
        gold_task.title = "Secret Gold Holdout Prompt"
        gold_task.save()
        TaskAnnotation.objects.create(
            task=gold_task,
            annotator=ann_expert,
            preference="response_a",
            response_a="Gold A",
            response_b="Gold B",
        )

        owner_client = _auth_client(owner, org)
        contrib_client = _auth_client(contrib, org)

        # 1. Streaming NDJSON export (default) excludes unresolved & gold tasks and scrubs PII
        stream_resp = owner_client.get(
            "/api/v1/tasks/export-dpo/?schema=chat&eval_ratio=0.35&split_seed=rel-v111"
        )
        assert stream_resp.status_code == 200
        assert stream_resp["Content-Type"] == "application/x-ndjson"
        lines = [
            json.loads(line)
            for line in b"".join(stream_resp.streaming_content).decode("utf-8").splitlines()
            if line.strip()
        ]
        assert len(lines) == 6
        assert {r["id"] for r in lines} == set(exported_ids)

        pii_row = next(r for r in lines if r["id"] == exported_ids[0])
        assert "[REDACTED_EMAIL]" in pii_row["prompt"]
        assert "[REDACTED_IP]" in pii_row["prompt"]
        assert "[REDACTED_SECRET]" in pii_row["prompt"]
        assert "[REDACTED_PHONE]" in pii_row["prompt"]
        assert "[REDACTED_SSN]" in pii_row["chosen"]
        assert "[REDACTED_EMAIL]" in pii_row["rationales"][0]
        assert "ops@acme.io" not in pii_row["prompt"]
        assert "123-45-6789" not in pii_row["chosen"]
        assert len(pii_row["chosen_messages"]) == 2
        assert pii_row["winning_skill_weight"] > 1.0

        # Deterministic split invariance: ?split=train + ?split=eval partitions the exact 6 rows
        train_lines = [
            json.loads(ln)
            for ln in b"".join(
                owner_client.get(
                    "/api/v1/tasks/export-dpo/?split=train&eval_ratio=0.35&split_seed=rel-v111"
                ).streaming_content
            )
            .decode("utf-8")
            .splitlines()
            if ln.strip()
        ]
        eval_lines = [
            json.loads(ln)
            for ln in b"".join(
                owner_client.get(
                    "/api/v1/tasks/export-dpo/?split=eval&eval_ratio=0.35&split_seed=rel-v111"
                ).streaming_content
            )
            .decode("utf-8")
            .splitlines()
            if ln.strip()
        ]
        assert {r["id"] for r in train_lines}.isdisjoint({r["id"] for r in eval_lines})
        assert len(train_lines) + len(eval_lines) == 6

        # 2. Signed provenance manifest + S3 archive upload + offline Ed25519 verification
        ed_priv_pem, ed_pub_pem = _ed25519_keypair_pems()

        # Non-admin contributor cannot archive exports to S3 -> 403
        assert (
            contrib_client.get(
                "/api/v1/tasks/export-dpo/?export_format=manifest&archive_to_s3=true"
            ).status_code
            == 403
        )

        fake_http_resp = MagicMock()
        fake_http_resp.status = 200
        fake_http_resp.read.return_value = b""
        fake_http_resp.getheader.side_effect = lambda h: '"etag-dpo-v111"' if h == "ETag" else ""

        with (
            override_settings(
                AUDIT_ANCHOR_ED25519_PRIVATE_KEY_PEM=ed_priv_pem,
                DATASET_EXPORT_S3_BUCKET="mltask-dpo-exports-prod",
                DATASET_EXPORT_S3_REGION="us-east-1",
            ),
            patch.dict(
                os.environ,
                {
                    "AWS_ACCESS_KEY_ID": "AKIADPOTEST123456",
                    "AWS_SECRET_ACCESS_KEY": "dpo-secret-access-key-test",
                },
                clear=False,
            ),
            patch("apps.tasks.dpo_export.http.client.HTTPSConnection") as mock_https,
        ):
            mock_https.return_value.getresponse.return_value = fake_http_resp
            manifest_resp = owner_client.get(
                "/api/v1/tasks/export-dpo/?export_format=manifest&archive_to_s3=true"
            )

        assert manifest_resp.status_code == 200
        m_body = manifest_resp.json()
        manifest = m_body["manifest"]
        records = m_body["records"]
        assert manifest["total_records"] == 6
        assert manifest["pii_redactions_total"] >= 6
        assert manifest["signature_algorithm"] == "Ed25519"
        assert manifest["merkle_root"] == compute_merkle_root([r["row_sha256"] for r in records])
        assert manifest["s3_archive_uri"].startswith("s3://mltask-dpo-exports-prod/dpo-exports/")
        assert verify_dpo_manifest_offline(manifest, ed_pub_pem)["valid"] is True
        assert OutboxEvent.objects.filter(organization=org, event_type="dataset.exported").exists()

        # 3. M2M OrganizationAPIKey scope check: tasks:read rejected (403), tasks:export allowed (200)
        _ro_obj, ro_raw = OrganizationAPIKey.create_with_raw_key(
            organization=org,
            created_by=owner,
            name="Read Only Key",
            role="contributor",
            scopes=["tasks:read"],
        )
        _ex_obj, ex_raw = OrganizationAPIKey.create_with_raw_key(
            organization=org,
            created_by=owner,
            name="DPO Export Key",
            role="contributor",
            scopes=["tasks:export"],
        )
        api_client = APIClient()
        api_client.credentials(HTTP_X_API_KEY=ro_raw)
        assert api_client.get("/api/v1/tasks/export-dpo/?export_format=json").status_code == 403
        api_client.credentials(HTTP_X_API_KEY=ex_raw)
        assert api_client.get("/api/v1/tasks/export-dpo/?export_format=json").status_code == 200

    def test_pii_scrubber_unit_precision(self) -> None:
        raw = (
            "Contact jane.doe@sub.example.org or 415-555-0188 with mlk_live_abcd1234_secret987654."
        )
        scrubbed, count = scrub_dataset_pii(raw)
        assert count == 3
        assert "jane.doe" not in scrubbed
        assert "415-555-0188" not in scrubbed
        assert "mlk_live_" not in scrubbed


@pytest.mark.django_db
class TestAdaptivePerDomainUncertaintyThresholds:
    """Verify empirical per-(organization, domain) threshold calibration & routing."""

    def setup_method(self) -> None:
        cache.clear()

    def test_unpredicted_domain_splits_lower_medical_threshold_and_escalate_future_tasks(
        self,
    ) -> None:
        owner = User.objects.create_user(email="adap-owner@example.com", password="Password123!")
        ann_1 = User.objects.create_user(email="adap-ann1@example.com", password="Password123!")
        ann_2 = User.objects.create_user(email="adap-ann2@example.com", password="Password123!")
        org = Organization.objects.create(
            name="Adaptive Threshold Org",
            slug="adaptive-threshold-org",
            plan="enterprise",
            max_users=25,
            max_tasks=100,
        )
        OrganizationMember.objects.create(organization=org, user=owner, role="owner")
        OrganizationMember.objects.create(organization=org, user=ann_1, role="contributor")
        OrganizationMember.objects.create(organization=org, user=ann_2, role="contributor")

        owner_client = _auth_client(owner, org)
        c1 = _auth_client(ann_1, org)
        c2 = _auth_client(ann_2, org)

        # Seed 3 'medical' tasks whose initial LLM judge uncertainty (~0.68) was BELOW default 0.78,
        # yet human annotators deadlocked 1-1 on all 3 -> triggers automatic downward calibration!
        for idx in range(3):
            med_task = Task.objects.create(
                user=owner,
                organization=org,
                domain="medical",
                difficulty="standard",
                priority="medium",
                required_annotations=2,
                uncertainty_score=0.68,
                judge_uncertainty_score=0.68,
            )
            med_task.set_current_language("en")
            med_task.title = f"Renal Dosing Adjustment Case #{idx}"
            med_task.description = "Evaluate borderline eGFR anticoagulation protocol."
            med_task.save()

            assert (
                c1.post(
                    f"/api/v1/tasks/{med_task.id}/annotations/",
                    {"preference": "response_a", "overall_score": 4},
                    format="json",
                ).status_code
                == 201
            )
            assert (
                c2.post(
                    f"/api/v1/tasks/{med_task.id}/annotations/",
                    {"preference": "response_b", "overall_score": 4},
                    format="json",
                ).status_code
                == 201
            )

        # Inspect calibrated policies via GET /api/v1/organizations/{org_id}/uncertainty-policies/
        pol_resp = owner_client.get(f"/api/v1/organizations/{org.id}/uncertainty-policies/")
        assert pol_resp.status_code == 200
        policies = {p["domain"]: p for p in pol_resp.json()["policies"]}
        assert policies["medical"]["threshold"] < 0.74
        assert policies["medical"]["split_vote_count"] == 3
        assert policies["medical"]["unpredicted_split_count"] == 3
        assert policies["code"]["threshold"] == 0.78
        assert policies["code"]["source"] == "global_default"
        assert OutboxEvent.objects.filter(
            organization=org,
            event_type="uncertainty.policy_calibrated",
        ).exists()

        # Now score an identical moderately uncertain distribution (0.64 / 0.30 / 0.06 -> score ~0.735):
        # In 'medical' (calibrated to 0.72) score ~0.757 escalates; in 'code' (0.78) it stays standard!
        moderate_mock = _mock_openai_completion(
            {
                "preference": "response_a",
                "choice_probabilities": {"response_a": 0.60, "response_b": 0.32, "tie": 0.08},
                "rationale": "Moderate clinical dosage tradeoff.",
            }
        )
        new_med_task = Task.objects.create(
            user=owner,
            organization=org,
            domain="medical",
            difficulty="standard",
            priority="medium",
        )
        new_med_task.set_current_language("en")
        new_med_task.title = "Hepatic Clearance Protocol"
        new_med_task.description = "Compare Child-Pugh B regimens."
        new_med_task.save()

        new_code_task = Task.objects.create(
            user=owner,
            organization=org,
            domain="code",
            difficulty="standard",
            priority="medium",
        )
        new_code_task.set_current_language("en")
        new_code_task.title = "Binary Search Helper"
        new_code_task.description = "Compare iterative vs recursive bisect."
        new_code_task.save()

        ai_svc = __import__("apps.ai_assist.services", fromlist=["_ai_service"])._ai_service
        fake_openai = MagicMock()
        fake_openai.chat.completions.create.return_value = moderate_mock
        with patch.object(ai_svc, "_client", fake_openai):
            med_triage = owner_client.post(
                f"/api/v1/tasks/{new_med_task.id}/triage-uncertainty/",
                {"response_a": "Protocol A", "response_b": "Protocol B"},
                format="json",
            )
            code_triage = owner_client.post(
                f"/api/v1/tasks/{new_code_task.id}/triage-uncertainty/",
                {"response_a": "Impl A", "response_b": "Impl B"},
                format="json",
            )

        assert med_triage.status_code == 200
        assert code_triage.status_code == 200
        assert med_triage.json()["triage"]["escalated_to_expert"] is True
        assert med_triage.json()["task"]["difficulty"] == "expert"
        assert code_triage.json()["triage"]["escalated_to_expert"] is False
        assert code_triage.json()["task"]["difficulty"] == "standard"

        # Admin can pin a custom domain policy, run on-demand calibration, and validate 400 guards
        pin_resp = owner_client.post(
            f"/api/v1/organizations/{org.id}/uncertainty-policies/",
            {"domain": "safety", "threshold": 0.55, "auto_calibrate": False},
            format="json",
        )
        assert pin_resp.status_code == 200
        pinned_safety = next(p for p in pin_resp.json()["policies"] if p["domain"] == "safety")
        assert pinned_safety["threshold"] == 0.55
        assert pinned_safety["source"] == "pinned"

        # Seed 3 'creative' tasks over-escalated by judge (0.85) that reached unanimous 1.0 consensus
        # -> upward threshold relaxation to save expert capacity!
        for idx in range(3):
            easy_task = Task.objects.create(
                user=owner,
                organization=org,
                domain="creative",
                status="completed",
                difficulty="expert",
                auto_escalated=True,
                consensus_choice="response_a",
                consensus_score=1.0,
                judge_uncertainty_score=0.85,
                required_annotations=1,
            )
            easy_task.set_current_language("en")
            easy_task.title = f"Unanimous Creative Prompt #{idx}"
            easy_task.save()
            TaskAnnotation.objects.create(
                task=easy_task,
                annotator=ann_1,
                preference="response_a",
                response_a="A",
                response_b="B",
            )

        on_demand_cal = owner_client.post(
            f"/api/v1/organizations/{org.id}/uncertainty-policies/",
            {"action": "calibrate", "min_samples": 3, "domain": "creative"},
            format="json",
        )
        assert on_demand_cal.status_code == 200
        creative_pol = next(
            p for p in on_demand_cal.json()["policies"] if p["domain"] == "creative"
        )
        assert creative_pol["threshold"] > 0.78

        # Validation error guards on uncertainty-policies & export-dpo & consistency-proof
        assert (
            owner_client.post(
                f"/api/v1/organizations/{org.id}/uncertainty-policies/",
                {"domain": "unknown_domain", "threshold": 0.5},
                format="json",
            ).status_code
            == 400
        )
        assert (
            owner_client.post(
                f"/api/v1/organizations/{org.id}/uncertainty-policies/",
                {"domain": "legal", "threshold": 1.5},
                format="json",
            ).status_code
            == 400
        )
        assert owner_client.get("/api/v1/tasks/export-dpo/?split=invalid").status_code == 400
        assert owner_client.get("/api/v1/tasks/export-dpo/?schema=invalid").status_code == 400
        assert (
            owner_client.get("/api/v1/tasks/export-dpo/?min_consensus_score=2.0").status_code == 400
        )
        assert (
            owner_client.get(
                f"/api/v1/organizations/{org.id}/audit-logs/checkpoints/consistency-proof/"
                "?from_seq=abc"
            ).status_code
            == 400
        )

        sweep = calibrate_adaptive_uncertainty_thresholds(min_samples=3, batch_size=25)
        assert sweep["organizations_evaluated"] >= 1
        assert DomainUncertaintyPolicy.objects.get(
            organization=org, domain="safety"
        ).threshold == pytest.approx(0.55)
        assert "calibrate-adaptive-uncertainty-thresholds" in settings.CELERY_BEAT_SCHEDULE


def test_terraform_v1110_dpo_dataset_export_bucket_and_lifecycle_iac() -> None:
    """Verify v1.11.0 encrypted S3 dataset export bucket, lifecycle & ECS env HCL."""
    tf_dir = Path(settings.BASE_DIR) / "terraform"
    main_tf = (tf_dir / "main.tf").read_text(encoding="utf-8")
    vars_tf = (tf_dir / "variables.tf").read_text(encoding="utf-8")
    outputs_tf = (tf_dir / "outputs.tf").read_text(encoding="utf-8")

    assert 'default     = "v1.11.0"' in vars_tf
    assert 'variable "enable_dataset_export_bucket"' in vars_tf
    assert 'variable "dataset_export_retention_days"' in vars_tf
    assert 'resource "aws_s3_bucket" "dataset_exports"' in main_tf
    assert 'resource "aws_s3_bucket_public_access_block" "dataset_exports"' in main_tf
    assert 'resource "aws_s3_bucket_lifecycle_configuration" "dataset_exports"' in main_tf
    assert 'storage_class = "GLACIER_IR"' in main_tf
    assert 'resource "aws_iam_role_policy" "ecs_task_dataset_exports"' in main_tf
    assert (
        '{ name = "DATASET_EXPORT_S3_BUCKET", value = local.dataset_export_bucket_name }' in main_tf
    )
    assert 'output "dataset_export_bucket_name"' in outputs_tf
