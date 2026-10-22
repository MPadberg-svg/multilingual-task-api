"""Tests for writable multilingual serializer, query-safe caching, N+1 bounds, and Celery tasks."""

from __future__ import annotations

import uuid
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core import mail
from django.core.cache import cache

import pytest
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.core.models import AuditLog, Organization
from apps.tasks.models import Task
from apps.tasks.tasks import (
    generate_task_translations,
    invalidate_task_cache,
    persist_audit_log,
    send_task_notification_email,
)

User = get_user_model()


@pytest.mark.django_db
class TestWritableMultilingualAndCaching:
    """Verify flat + nested translation writes, query-aware cache keys, and N+1 bounds."""

    def _auth_client(self, user) -> tuple[APIClient, str]:
        client = APIClient()
        token = str(RefreshToken.for_user(user).access_token)
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        return client, token

    def test_flat_and_nested_multilingual_create_and_partial_update(self):
        cache.clear()
        user = User.objects.create_user(email="writer@example.com", password="pw")
        client, _ = self._auth_client(user)

        # Create via flat title/description with French Accept-Language
        create_resp = client.post(
            "/api/v1/tasks/",
            {"title": "Tâche initiale — n°1 🚀", "description": "Description française"},
            format="json",
            HTTP_ACCEPT_LANGUAGE="fr",
        )
        assert create_resp.status_code == 201
        data = create_resp.json()
        task_id = data["id"]
        assert data["title"] == "Tâche initiale — n°1 🚀"
        assert data["translations"]["fr"]["title"] == "Tâche initiale — n°1 🚀"

        # Add Spanish + English translations via partial update without wiping French
        patch_resp = client.patch(
            f"/api/v1/tasks/{task_id}/",
            {
                "translations": {
                    "en": {"title": "Initial Task — #1 🚀", "description": "English desc"},
                    "es": {"title": "Tarea inicial — n.º 1 🚀", "description": "Desc español"},
                }
            },
            format="json",
            HTTP_ACCEPT_LANGUAGE="es",
        )
        assert patch_resp.status_code == 200
        patched = patch_resp.json()
        assert patched["title"] == "Tarea inicial — n.º 1 🚀"
        assert patched["translations"]["fr"]["title"] == "Tâche initiale — n°1 🚀"
        assert patched["translations"]["en"]["title"] == "Initial Task — #1 🚀"

    def test_serializer_rejects_xss_unsupported_language_and_missing_title(self):
        user = User.objects.create_user(email="val@example.com", password="pw")
        client, _ = self._auth_client(user)

        # Missing both title and translations
        r_empty = client.post("/api/v1/tasks/", {"status": "pending"}, format="json")
        assert r_empty.status_code == 400

        # Unsupported language key
        r_lang = client.post(
            "/api/v1/tasks/",
            {"translations": {"de": {"title": "Hallo"}}},
            format="json",
        )
        assert r_lang.status_code == 400

        # Pure script tag title becomes empty after sanitization -> 400
        r_xss = client.post(
            "/api/v1/tasks/",
            {"title": "<script>alert('xss')</script>"},
            format="json",
        )
        assert r_xss.status_code == 400

    def test_query_aware_cache_keys_do_not_collide_and_invalidate_across_languages(self):
        cache.clear()
        user = User.objects.create_user(email="cache@example.com", password="pw")
        client, _ = self._auth_client(user)

        t1 = Task.objects.create(user=user, status="pending")
        t1.set_current_language("en")
        t1.title = "Pending EN"
        t1.save()
        t1.set_current_language("es")
        t1.title = "Pendiente ES"
        t1.save()

        t2 = Task.objects.create(user=user, status="completed")
        t2.set_current_language("en")
        t2.title = "Completed EN"
        t2.save()

        # Populate EN unfiltered, ES unfiltered, and EN status=pending caches
        r_all_en = client.get("/api/v1/tasks/", HTTP_ACCEPT_LANGUAGE="en")
        r_pending_en = client.get("/api/v1/tasks/?status=pending", HTTP_ACCEPT_LANGUAGE="en")
        r_all_es = client.get("/api/v1/tasks/", HTTP_ACCEPT_LANGUAGE="es")
        r_detail_es = client.get(f"/api/v1/tasks/{t1.id}/", HTTP_ACCEPT_LANGUAGE="es")

        assert r_all_en.json()["count"] == 2
        assert r_pending_en.json()["count"] == 1
        assert r_all_es.json()["count"] == 2
        assert r_detail_es.json()["title"] == "Pendiente ES"

        # Update Spanish title while request is in EN -> must invalidate ES detail & list caches!
        client.patch(
            f"/api/v1/tasks/{t1.id}/",
            {"translations": {"es": {"title": "Actualizado ES"}}, "status": "completed"},
            format="json",
            HTTP_ACCEPT_LANGUAGE="en",
        )

        r_pending_after = client.get("/api/v1/tasks/?status=pending", HTTP_ACCEPT_LANGUAGE="en")
        r_detail_es_after = client.get(f"/api/v1/tasks/{t1.id}/", HTTP_ACCEPT_LANGUAGE="es")
        assert r_pending_after.json()["count"] == 0
        assert r_detail_es_after.json()["title"] == "Actualizado ES"

    def test_multilingual_search_deduplicates_tasks_matching_multiple_languages(self):
        cache.clear()
        user = User.objects.create_user(email="search@example.com", password="pw")
        client, _ = self._auth_client(user)

        task = Task.objects.create(user=user, status="pending")
        for lang_code in ("en", "es", "fr"):
            task.set_current_language(lang_code)
            task.title = f"RLHF annotation {lang_code}"
            task.description = "Shared keyword RLHF"
            task.save()

        resp = client.get("/api/v1/tasks/?search=RLHF")
        assert resp.status_code == 200
        assert resp.json()["count"] == 1
        assert len(resp.json()["results"]) == 1

    def test_task_list_has_no_n_plus_1_queries(self, django_assert_max_num_queries):
        cache.clear()
        user = User.objects.create_user(email="perf@example.com", password="pw")
        client, _ = self._auth_client(user)

        for idx in range(15):
            task = Task.objects.create(user=user, status="pending")
            for lang in ("en", "es", "fr"):
                task.set_current_language(lang)
                task.title = f"Task {idx} ({lang})"
                task.description = f"Desc {idx}"
                task.save()

        # Regardless of 15 tasks x 3 translations = 45 rows, query count stays constant (<= 6)
        with django_assert_max_num_queries(6):
            resp = client.get("/api/v1/tasks/")
        assert resp.status_code == 200
        assert resp.json()["count"] == 15


@pytest.mark.django_db
class TestCeleryTasksSuite:
    """Full unit coverage for apps/tasks/tasks.py background workers."""

    def test_generate_task_translations_translates_from_non_english_source(self):
        user = User.objects.create_user(email="celery@example.com", password="pw")
        org = Organization.objects.create(name="Celery Org", slug="celery-org")
        task = Task.objects.create(user=user, organization=org, status="pending")
        # Only Spanish exists initially — previously raised TranslationDoesNotExist!
        task.set_current_language("es")
        task.title = "Revisar datos"
        task.description = "Validar etiquetas del lote"
        task.save()

        ai_payload = {
            "en": {"title": "Review data", "description": "Validate batch labels"},
            "es": {"title": "Revisar datos", "description": "Validar etiquetas del lote"},
            "fr": {"title": "Examiner les données", "description": "Valider les étiquettes"},
        }
        with patch(
            "apps.ai_assist.services.AIService.suggest_task_translations", return_value=ai_payload
        ):
            result = generate_task_translations(str(task.id), "Revisar datos")

        assert result["en"]["title"] == "Review data"
        task.refresh_from_db()
        assert (
            task.safe_translation_getter("title", language_code="en", any_language=False)
            == "Review data"
        )
        assert (
            task.safe_translation_getter("title", language_code="fr", any_language=False)
            == "Examiner les données"
        )

    def test_generate_task_translations_handles_missing_task(self):
        missing = generate_task_translations(str(uuid.uuid4()), "Any text")
        assert missing == {}

    def test_invalidate_task_cache_and_persist_audit_log_workers(self):
        cache.clear()
        user = User.objects.create_user(email="audit@example.com", password="pw")
        org = Organization.objects.create(name="Audit Org", slug="audit-org")
        task = Task.objects.create(user=user, organization=org, status="pending")

        detail_key = f"mltask:task_detail:{user.id}:en:{task.id}"
        cache.set(detail_key, {"id": str(task.id)}, 300)
        invalidate_task_cache(str(task.id), str(user.id), str(org.id))
        assert cache.get(detail_key) is None

        persist_audit_log(
            org_id=str(org.id),
            action="task.created",
            resource_type="Task",
            resource_id=str(task.id),
            user_id=str(user.id),
            ip_address="203.0.113.10",
            user_agent="pytest-agent",
            metadata={"lang": "en"},
        )
        assert AuditLog.objects.filter(action="task.created", resource_id=str(task.id)).count() == 1

        # Missing org_id / user_id also persists gracefully
        persist_audit_log(
            org_id=str(uuid.uuid4()),
            action="system.event",
            resource_type="System",
            resource_id="sys-1",
            user_id=str(uuid.uuid4()),
            ip_address=None,
            user_agent="",
            metadata={},
        )
        assert AuditLog.objects.filter(action="system.event").count() == 1

    def test_send_task_notification_email_delivers_message_and_handles_missing(self):
        user = User.objects.create_user(email="notify@example.com", password="pw")
        task = Task.objects.create(user=user, status="in_progress")
        task.set_current_language("en")
        task.title = "Safety Benchmark"
        task.save()

        sent = send_task_notification_email(str(task.id), "updated")
        assert sent is True
        assert len(mail.outbox) == 1
        assert "Safety Benchmark" in mail.outbox[0].subject
        assert mail.outbox[0].to == ["notify@example.com"]

        missing = send_task_notification_email(str(uuid.uuid4()), "created")
        assert missing is False
