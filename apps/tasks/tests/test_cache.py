"""Cache behavior tests for the Task API.

Validates Redis-backed caching for list/detail endpoints, cache
isolation per language, invalidation on mutations, and TTL compliance.
"""

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.urls import reverse
from rest_framework.test import APIClient, APITestCase

from apps.tasks.models import Task

User = get_user_model()


class TestTaskCache(APITestCase):
    """Integration tests for Task API caching layer.

    All tests run against the full DRF view layer with Redis as the
    cache backend. The cache is cleared before each test to ensure
    isolation.
    """

    def setUp(self) -> None:
        """Set up the test user, authenticated client, and clear cache."""
        self.user = User.objects.create_user(
            email="cacheuser@example.com",
            password="testpass123",
        )
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
        cache.clear()

    def test_detail_endpoint_cache_hit_on_second_request(self) -> None:
        """The second identical GET should return cached data."""
        task = Task.objects.create(user=self.user, status="pending")
        task.set_current_language("en")
        task.title = "Cache Test"
        task.save()

        url = reverse("task-detail", kwargs={"pk": str(task.id)})

        r1 = self.client.get(url)
        self.assertEqual(r1.status_code, 200)

        cache_key = (
            f"mltask:task_detail:{self.user.id}:en:{task.id}"
        )
        self.assertIsNotNone(cache.get(cache_key))

        r2 = self.client.get(url)
        self.assertEqual(r2.status_code, 200)
        self.assertEqual(r1.content, r2.content)

    def test_list_endpoint_cache_isolation_per_language(self) -> None:
        """List caches are stored separately per language code."""
        task = Task.objects.create(user=self.user, status="pending")
        task.set_current_language("en")
        task.title = "English Title"
        task.save()
        task.set_current_language("es")
        task.title = "Título Español"
        task.save()

        self.client.get(reverse("task-list"), HTTP_ACCEPT_LANGUAGE="en")
        self.client.get(reverse("task-list"), HTTP_ACCEPT_LANGUAGE="es")

        en_key = f"mltask:task_list:{self.user.id}:en:"
        es_key = f"mltask:task_list:{self.user.id}:es:"

        self.assertIsNotNone(cache.get(en_key))
        self.assertIsNotNone(cache.get(es_key))
        # Content should differ because translations are different
        self.assertNotEqual(cache.get(en_key), cache.get(es_key))

    def test_cache_invalidation_on_update(self) -> None:
        """Updating a task clears its detail cache."""
        task = Task.objects.create(user=self.user, status="pending")
        task.set_current_language("en")
        task.title = "Before"
        task.save()

        url = reverse("task-detail", kwargs={"pk": str(task.id)})
        self.client.get(url)

        cache_key = (
            f"mltask:task_detail:{self.user.id}:en:{task.id}"
        )
        self.assertIsNotNone(cache.get(cache_key))

        self.client.patch(
            url,
            {"translations": {"en": {"title": "After"}}},
            format="json",
        )

        self.assertIsNone(cache.get(cache_key))

    def test_cache_invalidation_on_soft_delete(self) -> None:
        """Soft-deleting a task clears its detail cache."""
        task = Task.objects.create(user=self.user, status="pending")
        task.set_current_language("en")
        task.title = "Delete Me"
        task.save()

        url = reverse("task-detail", kwargs={"pk": str(task.id)})
        self.client.get(url)

        cache_key = (
            f"mltask:task_detail:{self.user.id}:en:{task.id}"
        )
        self.client.delete(url)

        self.assertIsNone(cache.get(cache_key))

    def test_cache_ttl_compliance(self) -> None:
        """List cache entries expire within the configured TTL (300s)."""
        Task.objects.create(user=self.user, status="pending")
        self.client.get(reverse("task-list"))

        cache_key = f"mltask:task_list:{self.user.id}:en:"
        self.assertIsNotNone(cache.get(cache_key))

        ttl = cache.ttl(cache_key)
        self.assertLessEqual(ttl, 300)
        self.assertGreater(ttl, 0)