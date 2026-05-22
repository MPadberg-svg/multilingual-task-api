"""Task API views with caching, filtering, and tenant scoping.

Provides:
    - ``TaskViewSet``: CRUD for tasks with Redis cache invalidation,
      django-filter integration, and organization-aware queryset filtering.
"""

import logging

from django.conf import settings
from django.core.cache import cache
from django.shortcuts import get_object_or_404
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters, status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from apps.tasks.filters import TaskFilter
from apps.tasks.models import Task
from apps.tasks.serializers import TaskSerializer

logger = logging.getLogger(__name__)

CACHE_TTL_LIST = settings.CACHE_TTL["task_list"]
CACHE_TTL_DETAIL = settings.CACHE_TTL["task_detail"]


def _cache_key(prefix: str, user_id: str, lang: str, suffix: str = "") -> str:
    """Build a standardised cache key.

    Args:
        prefix: Key namespace (e.g. ``task_list``).
        user_id: UUID of the requesting user.
        lang: Resolved language code.
        suffix: Optional trailing segment.

    Returns:
        Cache key string.
    """
    return f"mltask:{prefix}:{user_id}:{lang}:{suffix}"


class TaskViewSet(viewsets.ModelViewSet):
    """CRUD endpoint for tasks with caching and tenant scoping.

    Attributes:
        queryset: Base queryset (filtered dynamically in ``get_queryset``).
        serializer_class: ``TaskSerializer``.
        permission_classes: ``IsAuthenticated``.
        filter_backends: Search, ordering, and DjangoFilterBackend.
        filterset_class: ``TaskFilter``.
        search_fields: ``title``, ``description`` (translated).
        ordering_fields: ``created_at``, ``updated_at``, ``status``.
    """

    queryset = Task.objects.filter(is_active=True)
    serializer_class = TaskSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter,
    ]
    filterset_class = TaskFilter
    search_fields = ["translations__title", "translations__description"]
    ordering_fields = ["created_at", "updated_at", "status"]

    def get_queryset(self):
        """Return tenant-scoped or user-scoped queryset.

        If ``request.organization`` is resolved, filter by organization.
        Otherwise fall back to the authenticated user.

        Returns:
            Filtered queryset of active tasks.
        """
        organization = getattr(self.request, "organization", None)
        if organization is not None:
            return Task.objects.filter(
                organization=organization,
                is_active=True,
            )
        return Task.objects.filter(
            user=self.request.user,
            is_active=True,
        )

    def list(self, request, *args, **kwargs):
        """List tasks with Redis caching.

        Cache key: ``mltask:task_list:{user_id}:{lang}:``
        """
        user_id = str(request.user.id)
        lang = getattr(request, "language", "en")
        cache_key = _cache_key("task_list", user_id, lang)

        cached = cache.get(cache_key)
        if cached is not None:
            return Response(cached)

        response = super().list(request, *args, **kwargs)
        cache.set(cache_key, response.data, timeout=CACHE_TTL_LIST)
        return response

    def retrieve(self, request, *args, **kwargs):
        """Retrieve a single task with Redis caching.

        Cache key: ``mltask:task_detail:{user_id}:{lang}:{task_id}``
        """
        user_id = str(request.user.id)
        lang = getattr(request, "language", "en")
        task_id = kwargs.get("pk")
        cache_key = _cache_key("task_detail", user_id, lang, task_id)

        cached = cache.get(cache_key)
        if cached is not None:
            return Response(cached)

        response = super().retrieve(request, *args, **kwargs)
        cache.set(cache_key, response.data, timeout=CACHE_TTL_DETAIL)
        return response

    @action(detail=True, methods=["post"], url_path="restore")
    def restore(self, request, pk=None):
        """Restore a soft-deleted task.

        IMPORTANT: Must bypass get_queryset() which filters is_active=True.
        We use get_object_or_404 directly against the unfiltered queryset.

        Args:
            request: DRF Request.
            pk: Task UUID.

        Returns:
            Response with restored task data (200) or 400 if already active.
        """
        # Scope to the user's own tasks (or org tasks), including soft-deleted
        organization = getattr(request, "organization", None)
        if organization is not None:
            base_qs = Task.objects.filter(organization=organization)
        else:
            base_qs = Task.objects.filter(user=request.user)

        # Find the task regardless of is_active state
        task = get_object_or_404(base_qs, pk=pk)

        if task.is_active:
            return Response(
                {"error": "Task is already active."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        task.is_active = True
        task.save(update_fields=["is_active", "updated_at"])
        self._invalidate_list_cache()
        serializer = self.get_serializer(task)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def perform_create(self, serializer):
        """Create task and invalidate list cache."""
        instance = serializer.save(user=self.request.user)
        self._invalidate_list_cache()
        return instance

    def perform_update(self, serializer):
        """Update task and invalidate detail + list cache."""
        instance = serializer.save()
        self._invalidate_detail_cache(instance.id)
        self._invalidate_list_cache()
        return instance

    def perform_destroy(self, instance):
        """Soft-delete task and invalidate caches."""
        instance.delete()
        self._invalidate_detail_cache(instance.id)
        self._invalidate_list_cache()

    def _invalidate_list_cache(self):
        """Invalidate the user's task list cache."""
        user_id = str(self.request.user.id)
        lang = getattr(self.request, "language", "en")
        cache_key = _cache_key("task_list", user_id, lang)
        cache.delete(cache_key)

    def _invalidate_detail_cache(self, task_id: str):
        """Invalidate a single task detail cache."""
        user_id = str(self.request.user.id)
        lang = getattr(self.request, "language", "en")
        cache_key = _cache_key("task_detail", user_id, lang, task_id)
        cache.delete(cache_key)