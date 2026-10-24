"""Comprehensive v1.10.0 test suite covering:
1. Asymmetric Ed25519 & AWS KMS (ECDSA P-256 SigV4) Audit Transparency Signing, Public-Key JWK/PEM Discovery, and Zero-Secret Offline Verification Bundles.
2. Active-Learning Pairwise LLM Judge Uncertainty Scoring (/api/v1/ai/judge-pair/), Task Uncertainty Triage (/triage-uncertainty/), Claim Acquisition Ordering, and Split-Vote Expert Escalation.
3. Celery Broker Queue-Depth Prometheus Gauges, CloudWatch Backlog Beat Telemetry, and Terraform KMS + Custom-Metric Celery Autoscaling IaC.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import override_settings

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.core.audit_chain import clear_kms_public_key_cache, verify_checkpoint_offline_bundle
from apps.core.models import (
    AuditChainCheckpoint,
    AuditLog,
    Organization,
    OrganizationMember,
    OutboxEvent,
)
from apps.tasks.calibration import compute_bayesian_skill_weight
from apps.tasks.models import AnnotatorCalibration, Task
from apps.tasks.tasks import emit_backlog_autoscaling_telemetry

User = get_user_model()


def _auth_client(user: object, org: Organization | None = None) -> APIClient:
    client = APIClient()
    token = str(RefreshToken.for_user(user).access_token)  # type: ignore[arg-type]
    creds: dict[str, str] = {"HTTP_AUTHORIZATION": f"Bearer {token}"}
    if org is not None:
        creds["HTTP_X_ORGANIZATION_ID"] = str(org.id)
    client.credentials(**creds)
    return client


def _mock_openai_completion(payload_dict: dict[str, Any]) -> Any:
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=json.dumps(payload_dict)))],
        usage=SimpleNamespace(prompt_tokens=120, completion_tokens=60),
    )


@pytest.mark.django_db
class TestAsymmetricAuditTransparencyAndOfflineVerification:
    """Verify Ed25519 & AWS KMS ECDSA-SHA256 checkpoint signing and zero-secret verification."""

    def setup_method(self) -> None:
        clear_kms_public_key_cache()

    def test_ed25519_public_key_discovery_offline_bundle_and_tamper_detection(self) -> None:
        ed_priv = Ed25519PrivateKey.generate()
        ed_priv_pem = (
            ed_priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            .decode("ascii")
            .strip()
            .replace("\n", "\\n")
        )
        other_priv = Ed25519PrivateKey.generate()
        other_pub_pem = other_priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        owner = User.objects.create_user(email="ed-owner@example.com", password="Password123!")
        contrib = User.objects.create_user(email="ed-contrib@example.com", password="Password123!")
        outsider = User.objects.create_user(email="ed-out@example.com", password="Password123!")
        org = Organization.objects.create(
            name="Ed25519 Transparency Org",
            slug="ed25519-transparency-org",
            plan="enterprise",
        )
        OrganizationMember.objects.create(organization=org, user=owner, role="owner")
        OrganizationMember.objects.create(organization=org, user=contrib, role="contributor")

        owner_client = _auth_client(owner, org)
        contrib_client = _auth_client(contrib, org)
        outsider_client = _auth_client(outsider)

        for idx in range(1, 3):
            AuditLog.objects.create(
                organization=org,
                user=owner,
                action="created",
                resource_type="Task",
                resource_id=f"ed-task-{idx}",
            )

        pub_url = f"/api/v1/organizations/{org.id}/audit-logs/public-key/"
        ckpt_url = f"/api/v1/organizations/{org.id}/audit-logs/checkpoints/"

        assert contrib_client.get(pub_url).status_code == 403
        assert outsider_client.get(pub_url).status_code == 404

        with override_settings(
            AUDIT_ANCHOR_SIGNING_KEY="v1100-hmac-defense-in-depth",
            AUDIT_ANCHOR_ED25519_PRIVATE_KEY_PEM=ed_priv_pem,
        ):
            pub_resp = owner_client.get(pub_url)
            assert pub_resp.status_code == 200
            pub_data = pub_resp.json()
            assert pub_data["asymmetric_signing_enabled"] is True
            assert pub_data["signature_algorithm"] == "Ed25519"
            assert pub_data["jwk"]["kty"] == "OKP"
            assert pub_data["jwk"]["crv"] == "Ed25519"
            assert pub_data["jwk"]["alg"] == "EdDSA"
            auditor_pinned_pem = pub_data["public_key_pem"]

            ckpt_resp = owner_client.post(ckpt_url, {}, format="json")
            assert ckpt_resp.status_code == 201
            ckpt_json = ckpt_resp.json()
            assert ckpt_json["signature_algorithm"] == "Ed25519"
            assert ckpt_json["public_key_fingerprint"] == pub_data["public_key_fingerprint"]
            assert len(ckpt_json["asymmetric_signature"]) >= 80

            bundle_url = (
                f"/api/v1/organizations/{org.id}/audit-logs/checkpoints/{ckpt_json['id']}/bundle/"
            )
            assert contrib_client.get(bundle_url).status_code == 403
            bundle_resp = owner_client.get(bundle_url)
            assert bundle_resp.status_code == 200
            assert bundle_resp.headers["X-Query-Target"] == "primary"
            bundle = bundle_resp.json()
            assert bundle["offline_verification"]["valid"] is True

            verify_resp = owner_client.get(
                f"/api/v1/organizations/{org.id}/audit-logs/verify/"
            ).json()
            assert verify_resp["valid"] is True
            assert verify_resp["latest_signature_algorithm"] == "Ed25519"

        # External auditor verifies checkpoint completely offline with ZERO server secrets!
        with override_settings(
            SECRET_KEY="external-auditor-airgapped-machine",
            AUDIT_ANCHOR_SIGNING_KEY="",
            AUDIT_ANCHOR_ED25519_PRIVATE_KEY_PEM="",
        ):
            offline_ok = verify_checkpoint_offline_bundle(
                bundle["checkpoint"],
                auditor_pinned_pem,
            )
            assert offline_ok["valid"] is True
            assert offline_ok["reasons"] == []

            # Wrong public key is rejected immediately
            wrong_key_check = verify_checkpoint_offline_bundle(
                bundle["checkpoint"],
                other_pub_pem.decode("ascii"),
            )
            assert wrong_key_check["valid"] is False
            assert "checkpoint_public_key_mismatch" in wrong_key_check["reasons"]
            assert "checkpoint_asymmetric_signature_mismatch" in wrong_key_check["reasons"]

        # Corrupt asymmetric_signature in SQL while leaving HMAC untouched -> caught on verify!
        AuditChainCheckpoint.objects.filter(id=ckpt_json["id"]).update(
            asymmetric_signature="A" * 86
        )
        with override_settings(
            AUDIT_ANCHOR_SIGNING_KEY="v1100-hmac-defense-in-depth",
            AUDIT_ANCHOR_PUBLIC_KEY_PEM=auditor_pinned_pem,
        ):
            tampered_report = owner_client.get(
                f"/api/v1/organizations/{org.id}/audit-logs/verify/"
            ).json()
            assert tampered_report["valid"] is False
            assert tampered_report["checkpoint_valid"] is False
            assert (
                "checkpoint_asymmetric_signature_mismatch"
                in tampered_report["checkpoint_violations"][0]["reasons"]
            )

    def test_aws_kms_ecdsa_sha256_sigv4_signing_and_public_key_memoization(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

        kms_ec_priv = ec.generate_private_key(ec.SECP256R1())
        kms_pub_der = kms_ec_priv.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        kms_pub_pem = (
            kms_ec_priv.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("ascii")
        )

        owner = User.objects.create_user(email="kms-owner@example.com", password="Password123!")
        org = Organization.objects.create(name="KMS Audit Org", slug="kms-audit-org", plan="pro")
        OrganizationMember.objects.create(organization=org, user=owner, role="owner")
        AuditLog.objects.create(
            organization=org, user=owner, action="login", resource_type="Session"
        )

        kms_calls: list[dict[str, Any]] = []

        class _FakeKMSConnection:
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                self._resp_payload: dict[str, Any] = {}

            def request(self, method: str, uri: str, body: bytes, headers: dict[str, str]) -> None:
                target = headers["X-Amz-Target"]
                parsed = json.loads(body.decode("utf-8"))
                kms_calls.append(
                    {"method": method, "uri": uri, "target": target, "headers": headers}
                )
                if target == "TrentService.GetPublicKey":
                    self._resp_payload = {
                        "KeyId": parsed["KeyId"],
                        "PublicKey": base64.b64encode(kms_pub_der).decode("ascii"),
                    }
                elif target == "TrentService.Sign":
                    assert parsed["MessageType"] == "DIGEST"
                    assert parsed["SigningAlgorithm"] == "ECDSA_SHA_256"
                    digest_bytes = base64.b64decode(parsed["Message"])
                    from cryptography.hazmat.primitives.asymmetric import utils as asym_utils

                    sig = kms_ec_priv.sign(
                        digest_bytes,
                        ec.ECDSA(asym_utils.Prehashed(hashes.SHA256())),
                    )
                    self._resp_payload = {
                        "KeyId": parsed["KeyId"],
                        "Signature": base64.b64encode(sig).decode("ascii"),
                        "SigningAlgorithm": "ECDSA_SHA_256",
                    }

            def getresponse(self) -> Any:
                resp = MagicMock()
                resp.status = 200
                resp.read.return_value = json.dumps(self._resp_payload).encode("utf-8")
                return resp

            def close(self) -> None:
                return None

        owner_client = _auth_client(owner, org)
        kms_arn = "arn:aws:kms:us-east-1:123456789012:key/11112222-3333-4444-5555-666677778888"

        with (
            override_settings(
                AUDIT_ANCHOR_KMS_KEY_ID=kms_arn,
                AUDIT_WORM_S3_REGION="us-east-1",
            ),
            patch("apps.core.audit_chain.http.client.HTTPSConnection", _FakeKMSConnection),
        ):
            ckpt_1 = owner_client.post(
                f"/api/v1/organizations/{org.id}/audit-logs/checkpoints/",
                {},
                format="json",
            )
            assert ckpt_1.status_code == 201
            c1_data = ckpt_1.json()
            assert c1_data["signature_algorithm"] == "KMS-ECDSA-SHA256"
            # Minting checkpoint #1 wrote an AuditLog entry; mint checkpoint #2 to verify GetPublicKey cache!
            ckpt_2 = owner_client.post(
                f"/api/v1/organizations/{org.id}/audit-logs/checkpoints/",
                {},
                format="json",
            )
            assert ckpt_2.status_code == 201

            verify_kms = owner_client.get(
                f"/api/v1/organizations/{org.id}/audit-logs/verify/"
            ).json()
            assert verify_kms["valid"] is True
            assert verify_kms["checkpoints_verified"] == 2

            kms_pub_resp = owner_client.get(
                f"/api/v1/organizations/{org.id}/audit-logs/public-key/"
            ).json()
            assert kms_pub_resp["signature_algorithm"] == "KMS-ECDSA-SHA256"
            assert kms_pub_resp["jwk"]["kty"] == "EC"
            assert kms_pub_resp["jwk"]["crv"] == "P-256"
            assert kms_pub_resp["kms_key_configured"] is True

        targets = [c["target"] for c in kms_calls]
        assert targets.count("TrentService.Sign") == 2
        # GetPublicKey was called only ONCE thanks to _KMS_PUBLIC_KEY_DER_CACHE!
        assert targets.count("TrentService.GetPublicKey") == 1
        assert "/kms/aws4_request" in kms_calls[0]["headers"]["Authorization"]

        offline = verify_checkpoint_offline_bundle(c1_data, kms_pub_pem)
        assert offline["valid"] is True
        assert offline["signature_algorithm"] == "KMS-ECDSA-SHA256"


@pytest.mark.django_db
class TestActiveLearningUncertaintyRoutingAndEscalation:
    """Verify /ai/judge-pair/, /tasks/{id}/triage-uncertainty/, claim ordering & split-vote escalation."""

    def setup_method(self) -> None:
        cache.clear()

    def test_judge_pair_endpoint_and_task_uncertainty_triage_auto_escalation(self) -> None:
        owner = User.objects.create_user(email="al-owner@example.com", password="Password123!")
        org = Organization.objects.create(
            name="Active Learning Org",
            slug="active-learning-org",
            plan="enterprise",
            max_tasks=100,
        )
        OrganizationMember.objects.create(organization=org, user=owner, role="owner")
        client = _auth_client(owner, org)

        # XSS / SQLi injection & missing-field rejection on /api/v1/ai/judge-pair/
        assert (
            client.post(
                "/api/v1/ai/judge-pair/", {"prompt": "only prompt"}, format="json"
            ).status_code
            == 400
        )
        inj_resp = client.post(
            "/api/v1/ai/judge-pair/",
            {
                "prompt": "<script>alert(1)</script> DROP TABLE core_user;--",
                "response_a": "Answer A",
                "response_b": "Answer B",
            },
            format="json",
        )
        assert inj_resp.status_code == 400

        # 1. Decisive LLM judge score (0.93 / 0.05 / 0.02) -> low entropy, should_escalate=False
        decisive_mock = _mock_openai_completion(
            {
                "preference": "response_a",
                "choice_probabilities": {"response_a": 0.93, "response_b": 0.05, "tie": 0.02},
                "rationale": "Response A is strictly more accurate and complete.",
            }
        )
        ai_svc = __import__("apps.ai_assist.services", fromlist=["_ai_service"])._ai_service
        decisive_client = MagicMock()
        decisive_client.chat.completions.create.return_value = decisive_mock
        with patch.object(ai_svc, "_client", decisive_client):
            low_u = client.post(
                "/api/v1/ai/judge-pair/",
                {
                    "prompt": "Explain Python generators.",
                    "response_a": "Generators yield items lazily using yield.",
                    "response_b": "Generators are lists.",
                    "domain": "code",
                },
                format="json",
            )
            low_u_cached = client.post(
                "/api/v1/ai/judge-pair/",
                {
                    "prompt": "Explain Python generators.",
                    "response_a": "Generators yield items lazily using yield.",
                    "response_b": "Generators are lists.",
                    "domain": "code",
                },
                format="json",
            )
        assert low_u.status_code == 200
        assert low_u_cached.status_code == 200
        assert decisive_client.chat.completions.create.call_count == 1
        assert low_u.json()["should_escalate"] is False
        assert low_u.json()["uncertainty_score"] < 0.30

        # 2. Borderline task triaged via /api/v1/tasks/{id}/triage-uncertainty/ -> escalates to expert!
        task_resp = client.post(
            "/api/v1/tasks/",
            {
                "title": "Subtle Rust Send/Sync Lifetime Tradeoff",
                "description": "Compare lock-free arena vs Arc<Mutex<T>> latency.",
                "domain": "code",
                "difficulty": "standard",
                "priority": "medium",
            },
            format="json",
        )
        assert task_resp.status_code == 201
        task_id = task_resp.json()["id"]

        borderline_mock = _mock_openai_completion(
            {
                "preference": "response_a",
                "choice_probabilities": {"response_a": 0.49, "response_b": 0.46, "tie": 0.05},
                "rationale": "Both designs have nuanced tail-latency vs safety tradeoffs.",
            }
        )
        ai_svc = __import__("apps.ai_assist.services", fromlist=["_ai_service"])._ai_service
        fake_openai = MagicMock()
        fake_openai.chat.completions.create.return_value = borderline_mock
        with patch.object(ai_svc, "_client", fake_openai):
            triage_resp = client.post(
                f"/api/v1/tasks/{task_id}/triage-uncertainty/",
                {
                    "response_a": "Use Pin<Box<...>> with custom atomic refcount.",
                    "response_b": "Use crossbeam epoch-based reclamation.",
                },
                format="json",
            )

        assert triage_resp.status_code == 200
        body = triage_resp.json()
        assert body["triage"]["escalated_to_expert"] is True
        assert body["triage"]["uncertainty_score"] >= 0.85
        assert body["task"]["difficulty"] == "expert"
        assert body["task"]["priority"] == "high"
        assert body["task"]["auto_escalated"] is True
        assert body["task"]["uncertainty_score"] >= 0.85
        assert OutboxEvent.objects.filter(
            organization=org,
            event_type="task.uncertainty_escalated",
        ).exists()
        assert AuditLog.objects.filter(
            organization=org,
            action="task_uncertainty_triaged",
            resource_id=task_id,
        ).exists()

        # Filter tasks by ?min_uncertainty=0.80&auto_escalated=true
        filtered = client.get("/api/v1/tasks/?min_uncertainty=0.80&auto_escalated=true")
        assert filtered.status_code == 200
        assert [r["id"] for r in filtered.json()["results"]] == [task_id]

        # Verify CircuitOpenError (503 + Retry-After) & AIBudgetExceededError (429) on triage & judge
        from apps.ai_assist.circuit_breaker import CircuitOpenError
        from apps.core.finops import AIBudgetExceededError

        with patch.object(ai_svc, "judge_rlhf_pair", side_effect=CircuitOpenError("OPEN")):
            cb_triage = client.post(
                f"/api/v1/tasks/{task_id}/triage-uncertainty/",
                {"response_a": "A", "response_b": "B"},
                format="json",
            )
            cb_judge = client.post(
                "/api/v1/ai/judge-pair/",
                {"prompt": "P", "response_a": "A", "response_b": "B"},
                format="json",
            )
        assert cb_triage.status_code == 503
        assert "Retry-After" in cb_triage.headers
        assert cb_judge.status_code == 503

        budget_exc = AIBudgetExceededError(
            "Monthly token ceiling reached",
            budget_snapshot={"tokens_used": 1000, "token_limit": 1000},
        )
        with patch.object(ai_svc, "judge_rlhf_pair", side_effect=budget_exc):
            b_triage = client.post(
                f"/api/v1/tasks/{task_id}/triage-uncertainty/",
                {"response_a": "A", "response_b": "B"},
                format="json",
            )
            b_judge = client.post(
                "/api/v1/ai/judge-pair/",
                {"prompt": "P", "response_a": "A", "response_b": "B"},
                format="json",
            )
        assert b_triage.status_code == 429
        assert b_triage.json()["code"] == "ai_budget_exceeded"
        assert b_judge.status_code == 429

    def test_claim_acquires_highest_uncertainty_first_and_split_vote_promotes_to_expert(
        self,
    ) -> None:
        owner = User.objects.create_user(email="split-owner@example.com", password="Password123!")
        spec_user = User.objects.create_user(email="spec-al@example.com", password="Password123!")
        ann_2 = User.objects.create_user(email="ann2-al@example.com", password="Password123!")
        prob_user = User.objects.create_user(email="prob-al@example.com", password="Password123!")
        org = Organization.objects.create(
            name="Split Escalation Org",
            slug="split-escalation-org",
            plan="enterprise",
            max_users=25,
            max_tasks=100,
        )
        OrganizationMember.objects.create(organization=org, user=owner, role="owner")
        for u in (spec_user, ann_2, prob_user):
            OrganizationMember.objects.create(organization=org, user=u, role="contributor")

        _, high_w = compute_bayesian_skill_weight(4, 4)
        _, low_w = compute_bayesian_skill_weight(0, 4)
        for calibrated_u in (spec_user, ann_2):
            AnnotatorCalibration.objects.create(
                organization=org,
                user=calibrated_u,
                gold_evaluated_count=4,
                gold_correct_count=4,
                accuracy_rate=1.0,
                skill_weight=high_w,
            )
        AnnotatorCalibration.objects.create(
            organization=org,
            user=prob_user,
            gold_evaluated_count=4,
            gold_correct_count=0,
            accuracy_rate=0.0,
            skill_weight=low_w,
        )

        # Older low-uncertainty task vs newer high-uncertainty task of identical priority & domain
        low_u_task = Task.objects.create(
            user=owner,
            organization=org,
            priority="high",
            domain="math",
            difficulty="expert",
            uncertainty_score=0.18,
            required_annotations=2,
        )
        low_u_task.set_current_language("en")
        low_u_task.title = "Routine Integral Check"
        low_u_task.save()

        high_u_task = Task.objects.create(
            user=owner,
            organization=org,
            priority="high",
            domain="math",
            difficulty="expert",
            uncertainty_score=0.92,
            auto_escalated=True,
            required_annotations=2,
        )
        high_u_task.set_current_language("en")
        high_u_task.title = "Ambiguous Stochastic PDE Proof"
        high_u_task.save()

        # Probation annotator is blocked from expert tasks
        prob_client = _auth_client(prob_user, org)
        assert prob_client.post("/api/v1/tasks/claim/", {}, format="json").status_code == 204

        # Calibrated annotator acquires the higher-uncertainty task FIRST despite being created second!
        spec_client = _auth_client(spec_user, org)
        claimed = spec_client.post("/api/v1/tasks/claim/", {}, format="json")
        assert claimed.status_code == 200
        assert claimed.json()["id"] == str(high_u_task.id)

        # Now create a standard 2-annotator task and submit a deadlocked 1-1 split vote
        split_task = Task.objects.create(
            user=owner,
            organization=org,
            priority="medium",
            domain="legal",
            difficulty="standard",
            required_annotations=2,
        )
        split_task.set_current_language("en")
        split_task.title = "Cross-Border Indemnification Clause"
        split_task.save()

        ann2_client = _auth_client(ann_2, org)
        r1 = spec_client.post(
            f"/api/v1/tasks/{split_task.id}/annotations/",
            {"preference": "response_a", "overall_score": 4},
            format="json",
        )
        assert r1.status_code == 201
        r2 = ann2_client.post(
            f"/api/v1/tasks/{split_task.id}/annotations/",
            {"preference": "response_b", "overall_score": 4},
            format="json",
        )
        assert r2.status_code == 201
        consensus = r2.json()["consensus"]
        assert consensus["awaiting_adjudication"] is True
        assert consensus["difficulty"] == "expert"
        assert consensus["auto_escalated"] is True
        assert consensus["uncertainty_score"] >= 0.80
        assert OutboxEvent.objects.filter(
            organization=org,
            event_type="task.uncertainty_escalated",
            payload__reason="split_vote_deadlock",
        ).exists()


@pytest.mark.django_db
def test_prometheus_celery_queue_depth_metrics_and_beat_autoscaling_telemetry() -> None:
    """Verify /api/v1/metrics/ queue gauges and Beat structured AsyncBacklogTelemetry."""
    cache.clear()
    org = Organization.objects.create(name="Backlog Org", slug="backlog-org")
    OutboxEvent.objects.create(
        organization=org, event_type="task.created", payload={"n": 1}, status="pending"
    )
    OutboxEvent.objects.create(
        organization=org, event_type="task.completed", payload={"n": 2}, status="pending"
    )
    OutboxEvent.objects.create(
        organization=org, event_type="task.deleted", payload={"n": 3}, status="failed"
    )

    mocked_queues = {"celery": 11, "default": 4, "tasks": 9, "ai": 3}
    client = APIClient()
    with (
        override_settings(METRICS_AUTH_TOKEN="v1100-metrics-secret"),
        patch("apps.core.views._probe_celery_broker_queue_depths", return_value=mocked_queues),
    ):
        resp = client.get("/api/v1/metrics/", HTTP_X_METRICS_TOKEN="v1100-metrics-secret")
        assert resp.status_code == 200
        text = resp.content.decode("utf-8")
        assert 'mltask_celery_queue_depth{queue="celery"} 11' in text
        assert 'mltask_celery_queue_depth{queue="tasks"} 9' in text
        assert 'mltask_celery_queue_depth{queue="ai"} 3' in text
        assert "mltask_celery_queue_depth_total 27" in text
        assert "mltask_outbox_pending_events 2" in text
        assert "mltask_outbox_dead_letter_events 1" in text
        assert "mltask_async_backlog_total 29" in text

        beat_payload = emit_backlog_autoscaling_telemetry()
        assert beat_payload == {
            "event": "AsyncBacklogTelemetry",
            "AsyncBacklogDepth": 29,
            "CeleryQueueDepth": 27,
            "OutboxPendingDepth": 2,
            "OutboxDeadLetterDepth": 1,
        }

    beat_cfg = settings.CELERY_BEAT_SCHEDULE["emit-backlog-autoscaling-telemetry"]
    assert beat_cfg["task"] == "apps.tasks.tasks.emit_backlog_autoscaling_telemetry"
    assert beat_cfg["schedule"] == 60.0


def test_terraform_v1100_kms_transparency_and_celery_backlog_autoscaling_iac() -> None:
    """Verify v1.10.0 AWS KMS ECC_NIST_P256 audit key & Celery AsyncBacklogDepth autoscaling HCL."""
    tf_dir = Path(settings.BASE_DIR) / "terraform"
    main_tf = (tf_dir / "main.tf").read_text(encoding="utf-8")
    vars_tf = (tf_dir / "variables.tf").read_text(encoding="utf-8")
    outputs_tf = (tf_dir / "outputs.tf").read_text(encoding="utf-8")

    assert 'default     = "v1.10.0"' in vars_tf
    assert 'variable "enable_audit_kms_signing"' in vars_tf
    assert 'variable "celery_backlog_target_per_worker"' in vars_tf
    assert 'resource "aws_kms_key" "audit_anchor"' in main_tf
    assert 'key_usage                = "SIGN_VERIFY"' in main_tf
    assert 'customer_master_key_spec = "ECC_NIST_P256"' in main_tf
    assert 'resource "aws_iam_role_policy" "ecs_task_audit_kms"' in main_tf
    assert '{ name = "AUDIT_ANCHOR_KMS_KEY_ID", value = local.audit_kms_key_arn }' in main_tf
    assert 'resource "aws_appautoscaling_policy" "celery_backlog"' in main_tf
    assert "customized_metric_specification {" in main_tf
    assert 'metric_name = "AsyncBacklogDepth"' in main_tf
    assert 'resource "aws_cloudwatch_log_metric_filter" "async_backlog_depth"' in main_tf
    assert 'resource "aws_cloudwatch_metric_alarm" "celery_backlog_high"' in main_tf
    assert 'output "audit_kms_key_arn"' in outputs_tf
    assert 'output "celery_backlog_autoscaling_policy_arn"' in outputs_tf
