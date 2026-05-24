"""Unit tests for Celery task helpers in apps.tasks.tasks."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.test import override_settings

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
def test_generate_task_translations_returns_empty_when_task_missing():
    result = generate_task_translations.run("00000000-0000-0000-0000-000000000000", "hello")
    assert result == {}


@pytest.mark.django_db
def test_generate_task_translations_applies_all_languages():
    user = User.objects.create_user(email="celery@example.com", password="pass1234")
    task = Task.objects.create(user=user, status="pending")
    task.set_current_language("en")
    task.title = "Old EN"
    task.description = "Old EN desc"
    task.save()

    mocked = {
        "en": {"title": "Title EN", "description": "Desc EN"},
        "es": {"title": "Title ES", "description": "Desc ES"},
        "fr": {"title": "Title FR", "description": "Desc FR"},
    }

    with patch(
        "apps.tasks.tasks.AIService.suggest_task_translations",
        return_value=mocked,
    ):
        result = generate_task_translations.run(str(task.id), "translate me")

    task.refresh_from_db()
    assert result == mocked

    task.set_current_language("en")
    assert task.title == "Title EN"
    assert task.description == "Desc EN"
    task.set_current_language("es")
    assert task.title == "Title ES"
    assert task.description == "Desc ES"
    task.set_current_language("fr")
    assert task.title == "Title FR"
    assert task.description == "Desc FR"


@pytest.mark.django_db
def test_generate_task_translations_retries_on_ai_error():
    user = User.objects.create_user(email="retry@example.com", password="pass1234")
    task = Task.objects.create(user=user, status="pending")

    with patch(
        "apps.tasks.tasks.AIService.suggest_task_translations",
        side_effect=Exception("openai down"),
    ), patch.object(generate_task_translations, "retry", side_effect=RuntimeError("retrying")) as retry:
        with pytest.raises(RuntimeError, match="retrying"):
            generate_task_translations.run(str(task.id), "boom")
    retry.assert_called_once()


@override_settings(LANGUAGES=[("en", "English"), ("es", "Spanish"), ("fr", "French")])
def test_invalidate_task_cache_deletes_all_language_keys():
    with patch("apps.tasks.tasks.cache.delete") as delete:
        invalidate_task_cache.run(task_id="task-123", user_id="user-456")

    expected = {
        "mltask:task_list:user-456:en:",
        "mltask:task_detail:user-456:en:task-123",
        "mltask:task_list:user-456:es:",
        "mltask:task_detail:user-456:es:task-123",
        "mltask:task_list:user-456:fr:",
        "mltask:task_detail:user-456:fr:task-123",
    }
    called = {call.args[0] for call in delete.call_args_list}
    assert called == expected


@pytest.mark.django_db
def test_persist_audit_log_with_existing_org_and_user():
    user = User.objects.create_user(email="audit@example.com", password="pass1234")
    org = Organization.objects.create(name="Audit Org", slug="audit-org")

    persist_audit_log.run(
        org_id=str(org.id),
        action="created",
        resource_type="task",
        resource_id="abc",
        user_id=str(user.id),
        ip_address="127.0.0.1",
        user_agent="pytest",
        metadata={"k": "v"},
    )

    log = AuditLog.objects.get(resource_id="abc")
    assert log.organization == org
    assert log.user == user
    assert log.action == "created"
    assert log.metadata == {"k": "v"}


@pytest.mark.django_db
def test_persist_audit_log_with_missing_org_and_user():
    persist_audit_log.run(
        org_id="00000000-0000-0000-0000-000000000000",
        action="updated",
        resource_type="task",
        resource_id="missing",
        user_id="00000000-0000-0000-0000-000000000001",
        ip_address=None,
        user_agent="pytest",
        metadata={},
    )

    log = AuditLog.objects.get(resource_id="missing")
    assert log.organization is None
    assert log.user is None
    assert log.action == "updated"


def test_send_task_notification_email_logs_message():
    with patch("apps.tasks.tasks.logger.info") as log_info:
        send_task_notification_email.run(task_id="task-1", event_type="created")
    log_info.assert_called_once()
