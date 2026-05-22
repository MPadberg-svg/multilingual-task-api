"""API integration tests for the Task management endpoints.

Covers multilingual resolution, fallback behavior, CRUD operations,
soft-delete, and restore functionality.
"""

from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APIClient, APITestCase

from apps.tasks.models import Task

User = get_user_model()


class TestTaskAPI(APITestCase):
    """Integration tests for the Task API.

    All tests run against the full DRF view layer with an
    authenticated user. The ``APITestCase`` base class provides
    Django test database isolation.
    """

    def setUp(self) -> None:
        """Set up the test user and authenticated API client."""
        self.user = User.objects.create_user(
            email="test@example.com",     # ← FIXED: removed invalid `username=`
            password="testpass123",
        )
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    def test_list_tasks_returns_spanish_with_accept_language_header(self) -> None:
        """Tasks return Spanish translations when Accept-Language is 'es'."""
        task = Task.objects.create(user=self.user, status="pending")
        task.set_current_language("es")
        task.title = "Tarea de prueba"
        task.description = "Descripción en español"
        task.save()

        response = self.client.get(
            reverse("task-list"),
            HTTP_ACCEPT_LANGUAGE="es",
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("Tarea de prueba", str(response.data))

    def test_list_tasks_falls_back_to_english_for_missing_translation(self) -> None:
        """Tasks fall back to English when the requested translation is absent."""
        task = Task.objects.create(user=self.user, status="pending")
        task.set_current_language("en")
        task.title = "English Title"
        task.save()

        response = self.client.get(
            reverse("task-list"),
            HTTP_ACCEPT_LANGUAGE="fr",
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("English Title", str(response.data))

    def test_create_task_with_multilingual_fields_succeeds(self) -> None:
        """Creating a task with translations in multiple languages returns 201."""
        data = {
            "translations": {
                "en": {
                    "title": "English Task",
                    "description": "English Desc",
                },
                "es": {
                    "title": "Tarea Español",
                    "description": "Desc Español",
                },
            },
            "status": "pending",
        }

        response = self.client.post(
            reverse("task-list"),
            data,
            format="json",
        )

        self.assertEqual(response.status_code, 201)

    def test_update_task_only_modifies_active_language(self) -> None:
        """PATCH only updates the translation for the active request language."""
        task = Task.objects.create(user=self.user, status="pending")
        task.set_current_language("en")
        task.title = "Original"
        task.save()

        self.client.patch(
            reverse("task-detail", kwargs={"pk": str(task.id)}),
            {"translations": {"es": {"title": "Modificado"}}},
            format="json",
            HTTP_ACCEPT_LANGUAGE="es",
        )

        task.refresh_from_db()
        task.set_current_language("en")
        self.assertEqual(task.title, "Original")

    def test_soft_delete_task_sets_is_active_false(self) -> None:
        """DELETE soft-deletes the task by setting is_active to False."""
        task = Task.objects.create(user=self.user, status="pending")

        response = self.client.delete(
            reverse("task-detail", kwargs={"pk": str(task.id)}),
        )

        self.assertEqual(response.status_code, 204)
        task.refresh_from_db()
        self.assertFalse(task.is_active)

    def test_restore_soft_deleted_task(self) -> None:
        """POST to restore action reactivates a soft-deleted task."""
        task = Task.objects.create(
            user=self.user,
            status="pending",
            is_active=False,
        )

        response = self.client.post(
            reverse("task-restore", kwargs={"pk": str(task.id)}),
        )

        self.assertEqual(response.status_code, 200)
        task.refresh_from_db()
        self.assertTrue(task.is_active)