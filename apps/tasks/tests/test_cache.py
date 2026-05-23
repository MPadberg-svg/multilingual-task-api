"""Tests for Task caching behavior: TTL, invalidation, and language scoping."""

from unittest.mock import MagicMock, patch

from django.core.cache import cache
from django.urls import reverse

import pytest
from rest_framework.test import APIClient


@pytest.fixture(autouse=True)
def patch_redis_for_signals(monkeypatch):
    """Ensure EventPublisher in signals uses a fake Redis connection."""
    fake_redis = MagicMock()
    fake_redis.publish = MagicMock(return_value=1)
    monkeypatch.setattr("apps.core.events.get_redis_connection", lambda name: fake_redis)


@pytest.mark.django_db
class TestTaskCache:
    """Cache behavior tests for task list and detail endpoints."""

    @pytest.fixture(autouse=True)
    def _use_locmem_cache(self, settings):
        """Override cache backend to in-memory for tests (no Redis required)."""
        settings.CACHES = {
            "default": {
                "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            }
        }

    def setup_method(self):
        """Set up authenticated client and clear cache before each test."""
        from django.contrib.auth import get_user_model

        self.client = APIClient()
        self.user = get_user_model().objects.create_user(
            email="cacheuser@example.com",
            password="cachepass123",
        )
        self.client.force_authenticate(user=self.user)
        cache.clear()

    def _create_task(self, title="Test Task", status="pending", lang="en"):
        """Helper to create a task with translations."""
        from apps.tasks.models import Task

        task = Task.objects.create(user=self.user, status=status)
        task.set_current_language(lang)
        task.title = title
        task.description = "Test description"
        task.save()
        return task

    def _get_title(self, task_data):
        """Extract title from serializer response (handles both list and detail formats)."""
        translations = task_data.get("translations", {})
        if translations and isinstance(translations, dict):
            lang = task_data.get("language", "en")
            if lang in translations and "title" in translations[lang]:
                return translations[lang]["title"]
        return task_data.get("title", "")

    def _list_cache_key(self, lang="en"):
        """Build the list cache key for the current user."""
        return f"mltask:task_list:{self.user.id}:{lang}:"

    # ------------------------------------------------------------------
    # 1. Language-specific cache keys
    # ------------------------------------------------------------------
    def test_cache_key_is_language_specific(self):
        """EN and ES requests must produce different cache keys."""
        task = self._create_task(title="English Task", lang="en")
        task.set_current_language("es")
        task.title = "Tarea Español"
        task.save()

        keys_set = []

        def capture_set(key, value, timeout=None, **kwargs):
            keys_set.append(key)
            return True

        with patch("apps.tasks.views.cache.set", side_effect=capture_set):
            self.client.get(reverse("task-list"), HTTP_ACCEPT_LANGUAGE="en")
            self.client.get(reverse("task-list"), HTTP_ACCEPT_LANGUAGE="es")

        en_keys = [k for k in keys_set if ":en:" in k]
        es_keys = [k for k in keys_set if ":es:" in k]

        assert len(en_keys) > 0, f"No EN cache key found. Keys: {keys_set}"
        assert len(es_keys) > 0, f"No ES cache key found. Keys: {keys_set}"
        assert en_keys[0] != es_keys[0], "EN and ES keys should differ"

    # ------------------------------------------------------------------
    # 2. Soft-delete invalidates list cache
    # ------------------------------------------------------------------
    def test_soft_delete_invalidates_cache(self):
        """Soft deleting a task must remove it from list cache."""
        task = self._create_task(title="Cached Task")

        response1 = self.client.get(reverse("task-list"))
        assert response1.status_code == 200
        assert any(str(t["id"]) == str(task.id) for t in response1.data.get("results", []))

        delete_response = self.client.delete(
            reverse("task-detail", kwargs={"pk": str(task.id)}),
        )
        assert delete_response.status_code in (204, 200)

        response2 = self.client.get(reverse("task-list"))
        assert response2.status_code == 200
        task_ids = [str(t["id"]) for t in response2.data.get("results", [])]
        assert str(task.id) not in task_ids, "Soft-deleted task still in cached list"

    # ------------------------------------------------------------------
    # 3. List cache TTL = 300s (5 minutes)
    # ------------------------------------------------------------------
    def test_list_cache_ttl_is_5_minutes(self):
        """Task list cache expires after 300 seconds."""
        self._create_task(title="TTL List Task")

        calls = []

        def capture_set(key, value, timeout=None, **kwargs):
            calls.append({"key": key, "timeout": timeout})
            return True

        with patch("apps.tasks.views.cache.set", side_effect=capture_set):
            self.client.get(reverse("task-list"))

        list_calls = [c for c in calls if "task_list" in c["key"]]
        assert len(list_calls) > 0, "List cache.set was never called"
        assert (
            list_calls[0]["timeout"] == 300
        ), f"Expected list TTL 300s, got {list_calls[0]['timeout']}"

    # ------------------------------------------------------------------
    # 4. Detail cache TTL = 600s (10 minutes)
    # ------------------------------------------------------------------
    def test_detail_cache_ttl_is_10_minutes(self):
        """Task detail cache expires after 600 seconds."""
        task = self._create_task(title="TTL Detail Task")

        calls = []

        def capture_set(key, value, timeout=None, **kwargs):
            calls.append({"key": key, "timeout": timeout})
            return True

        with patch("apps.tasks.views.cache.set", side_effect=capture_set):
            self.client.get(reverse("task-detail", kwargs={"pk": str(task.id)}))

        detail_calls = [c for c in calls if "task_detail" in c["key"]]
        assert len(detail_calls) > 0, "Detail cache.set was never called"
        assert (
            detail_calls[0]["timeout"] == 600
        ), f"Expected detail TTL 600s, got {detail_calls[0]['timeout']}"

    # ------------------------------------------------------------------
    # 5. Create task invalidates list cache
    # ------------------------------------------------------------------
    def test_create_task_invalidates_list_cache(self):
        """Creating a new task clears the list cache."""
        # Populate list cache with existing task
        self._create_task(title="Existing Task")
        self.client.get(reverse("task-list"))

        # Verify cache was populated
        cache_key = self._list_cache_key("en")
        assert cache.get(cache_key) is not None, "List cache should be populated"

        # Create a new task via API (perform_create triggers _invalidate_list_cache)
        data = {
            "translations": {
                "en": {
                    "title": "New Task",
                    "description": "New description",
                }
            },
            "status": "pending",
        }
        create_response = self.client.post(
            reverse("task-list"),
            data=data,
            format="json",
        )
        assert create_response.status_code == 201

        # Cache should be invalidated (deleted) after create
        assert cache.get(cache_key) is None, "List cache should be invalidated after create"

    # ------------------------------------------------------------------
    # 6. Update task invalidates detail cache
    # ------------------------------------------------------------------
    def test_update_task_invalidates_detail_cache(self):
        """Updating a task clears its detail cache."""
        task = self._create_task(title="Original Title")

        detail_url = reverse("task-detail", kwargs={"pk": str(task.id)})

        # Populate detail cache
        r1 = self.client.get(detail_url)
        assert r1.status_code == 200

        # Verify cache was populated
        cache_key = f"mltask:task_detail:{self.user.id}:en:{task.id}"
        assert cache.get(cache_key) is not None, "Detail cache should be populated"

        # Update via API (perform_update triggers _invalidate_detail_cache)
        update_data = {
            "translations": {
                "en": {
                    "title": "Updated Title",
                    "description": "Updated description",
                }
            },
            "status": "pending",
        }
        update_response = self.client.patch(detail_url, data=update_data, format="json")
        assert update_response.status_code == 200

        # Cache should be invalidated (deleted) after update
        assert cache.get(cache_key) is None, "Detail cache should be invalidated after update"
