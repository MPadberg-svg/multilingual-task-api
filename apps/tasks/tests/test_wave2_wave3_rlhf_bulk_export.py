"""Tests for Wave 2 & Wave 3: RLHF Task Leasing, Annotations, Consensus, Adjudication, Bulk, JSONL Export & Auto-Translation."""

from __future__ import annotations

import json
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.utils import timezone

import pytest
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.core.models import Organization, OrganizationMember
from apps.tasks.models import Task
from apps.tasks.tasks import generate_task_translations

User = get_user_model()


def _client_for(user: User, org: Organization | None = None, lang: str = "en") -> APIClient:
    client = APIClient()
    refresh = RefreshToken.for_user(user)
    headers: dict[str, str] = {
        "HTTP_AUTHORIZATION": f"Bearer {refresh.access_token}",
        "HTTP_ACCEPT_LANGUAGE": lang,
    }
    if org is not None:
        headers["HTTP_X_ORGANIZATION_ID"] = str(org.id)
    client.credentials(**headers)
    return client


@pytest.mark.django_db
class TestRLHFClaimAnnotateConsensusAndAdjudicate:
    """End-to-end RLHF task leasing, rubric annotation, consensus agreement, and split adjudication."""

    def setup_method(self) -> None:
        cache.clear()

    def test_majority_consensus_auto_completes_task(self) -> None:
        owner = User.objects.create_user(email="lead@rlhf.ai", password="Password123!")
        ann1 = User.objects.create_user(email="ann1@rlhf.ai", password="Password123!")
        ann2 = User.objects.create_user(email="ann2@rlhf.ai", password="Password123!")

        org = Organization.objects.create(
            name="RLHF Org", slug="rlhf-org", plan="enterprise", max_users=10, max_tasks=100
        )
        OrganizationMember.objects.create(organization=org, user=owner, role="owner")
        OrganizationMember.objects.create(organization=org, user=ann1, role="contributor")
        OrganizationMember.objects.create(organization=org, user=ann2, role="contributor")

        owner_client = _client_for(owner, org)
        ann1_es_client = _client_for(ann1, org, lang="es")
        ann2_fr_client = _client_for(ann2, org, lang="fr")

        # Create low-priority and critical-priority tasks (required_annotations=2)
        owner_client.post(
            "/api/v1/tasks/",
            {
                "translations": {"en": {"title": "Low priority item"}},
                "priority": "low",
                "required_annotations": 2,
            },
            format="json",
        )
        crit_resp = owner_client.post(
            "/api/v1/tasks/",
            {
                "translations": {
                    "en": {"title": "Compare assistant responses"},
                    "es": {"title": "Comparar respuestas del asistente"},
                    "fr": {"title": "Comparer les réponses de l'assistant"},
                },
                "priority": "critical",
                "required_annotations": 2,
            },
            format="json",
        )
        assert crit_resp.status_code == 201
        crit_id = crit_resp.data["id"]

        # Annotator 1 claims highest-priority task in Spanish
        claim1 = ann1_es_client.post("/api/v1/tasks/claim/", {"lease_seconds": 600}, format="json")
        assert claim1.status_code == 200
        assert claim1.data["id"] == crit_id
        assert claim1.data["title"] == "Comparar respuestas del asistente"
        assert claim1.data["status"] == "in_progress"

        # While leased to Annotator 1, Annotator 2 cannot submit an annotation directly to crit_id
        conflict = ann2_fr_client.post(
            f"/api/v1/tasks/{crit_id}/annotations/",
            {
                "preference_choice": "a",
                "overall_score": 5,
                "helpfulness_score": 5,
                "harmlessness_score": 5,
                "honesty_score": 5,
                "rationale": "Response A is safer",
            },
            format="json",
        )
        assert conflict.status_code == 409

        # Annotator 1 submits annotation -> 1/2 annotations, lease released, status stays in_progress
        sub1 = ann1_es_client.post(
            f"/api/v1/tasks/{crit_id}/annotations/",
            {
                "preference_choice": "a",
                "overall_score": 5,
                "helpfulness_score": 4,
                "harmlessness_score": 5,
                "honesty_score": 5,
                "rationale": "Respuesta A sigue todas las restricciones.",
                "duration_ms": 14200,
            },
            format="json",
        )
        assert sub1.status_code == 201
        assert sub1.data["consensus"]["consensus_reached"] is False

        # Duplicate submission by Annotator 1 is blocked with 409
        dup = ann1_es_client.post(
            f"/api/v1/tasks/{crit_id}/annotations/",
            {"preference_choice": "a", "overall_score": 5},
            format="json",
        )
        assert dup.status_code == 409

        # Annotator 2 now claims the same critical task in French!
        claim2 = ann2_fr_client.post("/api/v1/tasks/claim/", {"lease_seconds": 600}, format="json")
        assert claim2.status_code == 200
        assert claim2.data["id"] == crit_id
        assert claim2.data["title"] == "Comparer les réponses de l'assistant"

        # Annotator 2 agrees on choice "a" -> consensus reached (1.0), task auto-completed!
        sub2 = ann2_fr_client.post(
            f"/api/v1/tasks/{crit_id}/annotations/",
            {
                "preference_choice": "a",
                "overall_score": 4,
                "helpfulness_score": 4,
                "harmlessness_score": 5,
                "honesty_score": 4,
                "rationale": "La réponse A est exacte.",
                "duration_ms": 11800,
            },
            format="json",
        )
        assert sub2.status_code == 201
        assert sub2.data["consensus"]["consensus_reached"] is True
        assert sub2.data["consensus"]["consensus_choice"] == "response_a"
        assert sub2.data["consensus"]["consensus_score"] == 1.0

        task_db = Task.objects.get(id=crit_id)
        assert task_db.status == "completed"
        assert task_db.consensus_choice == "response_a"

    def test_split_vote_requires_admin_adjudication_and_expired_lease_reclaim(self) -> None:
        owner = User.objects.create_user(email="owner-split@rlhf.ai", password="Password123!")
        ann1 = User.objects.create_user(email="s1@rlhf.ai", password="Password123!")
        ann2 = User.objects.create_user(email="s2@rlhf.ai", password="Password123!")

        org = Organization.objects.create(
            name="Split Org", slug="split-org", plan="pro", max_users=10, max_tasks=100
        )
        OrganizationMember.objects.create(organization=org, user=owner, role="owner")
        OrganizationMember.objects.create(organization=org, user=ann1, role="contributor")
        OrganizationMember.objects.create(organization=org, user=ann2, role="contributor")

        owner_c = _client_for(owner, org)
        c1 = _client_for(ann1, org)
        c2 = _client_for(ann2, org)

        t_resp = owner_c.post(
            "/api/v1/tasks/",
            {"title": "Ambiguous edge case", "required_annotations": 2},
            format="json",
        )
        tid = t_resp.data["id"]

        # Simulate expired lease held by ann1 -> ann2 can reclaim it
        Task.objects.filter(id=tid).update(
            claimed_by=ann1, claimed_until=timezone.now() - timedelta(minutes=5)
        )
        reclaim = c2.post("/api/v1/tasks/claim/", {}, format="json")
        assert reclaim.status_code == 200
        assert reclaim.data["id"] == tid

        # ann2 votes "b", ann1 votes "a" -> 50/50 split -> awaiting_adjudication=True
        r2 = c2.post(
            f"/api/v1/tasks/{tid}/annotations/",
            {"preference_choice": "b", "overall_score": 4},
            format="json",
        )
        assert r2.status_code == 201
        r1 = c1.post(
            f"/api/v1/tasks/{tid}/annotations/",
            {"preference_choice": "a", "overall_score": 4},
            format="json",
        )
        assert r1.status_code == 201
        assert r1.data["consensus"]["consensus_reached"] is False
        assert r1.data["consensus"]["awaiting_adjudication"] is True

        # Contributor cannot adjudicate (403 from TenantPermissionMiddleware)
        forbidden = c1.post(
            f"/api/v1/tasks/{tid}/adjudicate/",
            {"consensus_choice": "b", "rationale": "Try to self-adjudicate"},
            format="json",
        )
        assert forbidden.status_code == 403

        # Owner adjudicates -> task becomes completed with gold consensus_choice="b"
        adj = owner_c.post(
            f"/api/v1/tasks/{tid}/adjudicate/",
            {"consensus_choice": "b", "rationale": "Response B cites primary source"},
            format="json",
        )
        assert adj.status_code == 200
        assert adj.data["status"] == "completed"
        assert adj.data["consensus_choice"] == "response_b"


@pytest.mark.django_db
class TestBulkIngestStreamingExportAndAutoTranslate:
    """Verify /tasks/bulk/ atomic quota guards, /tasks/export/?format=jsonl, and auto_translate."""

    def setup_method(self) -> None:
        cache.clear()

    def test_bulk_create_and_quota_enforcement_and_streaming_jsonl_export(self) -> None:
        owner = User.objects.create_user(email="bulk@rlhf.ai", password="Password123!")
        org = Organization.objects.create(
            name="Dataset Org", slug="dataset-org", plan="free", max_tasks=3
        )
        OrganizationMember.objects.create(organization=org, user=owner, role="owner")
        client = _client_for(owner, org)

        # Batch of 4 exceeds max_tasks=3 -> rejected atomically (0 created)
        over_quota = client.post(
            "/api/v1/tasks/bulk/",
            {"tasks": [{"title": f"Task {i}"} for i in range(4)]},
            format="json",
        )
        assert over_quota.status_code == 403
        assert Task.objects.filter(organization=org).count() == 0

        # Batch of 2 within max_tasks=3 -> 201 Created
        ok_bulk = client.post(
            "/api/v1/tasks/bulk/",
            {
                "tasks": [
                    {"title": "Prompt Alpha", "priority": "high"},
                    {"title": "Prompt Beta", "priority": "medium"},
                ]
            },
            format="json",
        )
        assert ok_bulk.status_code == 201
        assert ok_bulk.data["count"] == 2

        # Export as streaming JSONL via ?format=jsonl
        export_resp = client.get("/api/v1/tasks/export/?format=jsonl")
        assert export_resp.status_code == 200
        assert "application/x-ndjson" in export_resp["Content-Type"]
        raw_stream = b"".join(export_resp.streaming_content).decode("utf-8").strip().splitlines()
        assert len(raw_stream) == 2
        parsed_first = json.loads(raw_stream[0])
        assert "translations" in parsed_first
        assert "annotations" in parsed_first

    @pytest.mark.django_db(transaction=True)
    def test_auto_translate_triggers_celery_and_populates_translations(self) -> None:
        user = User.objects.create_user(email="trans@rlhf.ai", password="Password123!")
        org = Organization.objects.create(name="Trans Org", slug="trans-org", max_tasks=50)
        OrganizationMember.objects.create(organization=org, user=user, role="owner")
        client = _client_for(user, org)

        with patch("apps.tasks.tasks.generate_task_translations.delay") as mock_delay:
            resp = client.post(
                "/api/v1/tasks/",
                {
                    "title": "Audit financial summary",
                    "description": "Verify numbers match filings",
                    "auto_translate": True,
                },
                format="json",
            )
            assert resp.status_code == 201
            task_id = resp.data["id"]
            mock_delay.assert_called_once()

        fake_translations = {
            "en": {"title": "Audit financial summary", "description": "Verify numbers"},
            "es": {"title": "Auditar resumen financiero", "description": "Verificar cifras"},
            "fr": {"title": "Auditer le résumé financier", "description": "Vérifier les chiffres"},
        }
        with (
            patch(
                "apps.ai_assist.services.AIService.suggest_task_translations",
                return_value=fake_translations,
            ),
            patch("apps.tasks.tasks.broadcast_task_websocket_event") as mock_ws,
        ):
            out = generate_task_translations(task_id, "Audit financial summary")
            assert "es" in out
            mock_ws.assert_called_once()

        es_client = _client_for(user, org, lang="es")
        detail = es_client.get(f"/api/v1/tasks/{task_id}/")
        assert detail.status_code == 200
        assert detail.data["title"] == "Auditar resumen financiero"
