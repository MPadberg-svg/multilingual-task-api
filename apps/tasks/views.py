"""Task API views with query-aware Redis caching, N+1 prevention, and tenant scoping.

Provides:
    - ``TaskViewSet``: CRUD for tasks with multi-language cache invalidation,
      django-filter integration, and organization-aware queryset filtering.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any
from urllib.parse import urlencode

from django.conf import settings
from django.core.cache import cache
from django.db.models import QuerySet
from django.shortcuts import get_object_or_404

from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters, status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response

from apps.core.views import record_cache_hit, record_cache_miss
from apps.tasks.filters import TaskFilter
from apps.tasks.models import Task
from apps.tasks.serializers import TaskSerializer

logger = logging.getLogger(__name__)

CACHE_TTL_LIST: int = settings.CACHE_TTL["task_list"]
CACHE_TTL_DETAIL: int = settings.CACHE_TTL["task_detail"]


def _cache_key(prefix: str, scope_id: str, lang: str, suffix: str = "") -> str:
    """Build a standardised cache key."""
    return f"mltask:{prefix}:{scope_id}:{lang}:{suffix}"


def _cache_index_key(scope_id: str) -> str:
    """Registry key tracking active dynamic cache keys for ``scope_id``."""
    return f"mltask:cache_index:{scope_id}"


def _scope_id_for_request(request: Request) -> str:
    """Return tenant scope identifier (``org:<uuid>`` or ``<user_uuid>``)."""
    organization = getattr(request, "organization", None)
    if organization is not None:
        return f"org:{organization.id}"
    return str(request.user.id)


def _query_fingerprint(request: Request) -> str:
    """Deterministic digest of query parameters excluding ``lang``.

    Returns ``""`` when no filter/pagination/ordering query parameters are
    present so the default list cache key matches ``mltask:task_list:{id}:{lang}:``.
    """
    items: list[tuple[str, str]] = []
    for key in sorted(request.query_params.keys()):
        if key.lower() == "lang":
            continue
        for val in sorted(request.query_params.getlist(key)):
            items.append((key, val))
    if not items:
        return ""
    canonical = urlencode(items)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def register_scope_cache_key(scope_id: str, key: str) -> None:
    """Track ``key`` under ``scope_id`` so mutations can invalidate all variants."""
    idx_key = _cache_index_key(scope_id)
    try:
        tracked = cache.get(idx_key)
        key_set = set(tracked) if isinstance(tracked, (list, set, tuple)) else set()
        if key not in key_set:
            key_set.add(key)
            cache.set(idx_key, list(key_set), timeout=max(CACHE_TTL_LIST, CACHE_TTL_DETAIL))
    except Exception:
        logger.debug("Unable to update cache key index for %s", scope_id, exc_info=True)


def invalidate_task_caches_for_scopes(
    scope_ids: list[str],
    task_id: str | None = None,
) -> None:
    """Invalidate list and detail caches across all configured languages and query variants."""
    languages = [str(code).lower() for code, _ in getattr(settings, "LANGUAGES", [("en", "EN")])]

    for scope_id in set(scope_ids):
        if not scope_id:
            continue
        keys_to_delete: set[str] = set()
        for lang in languages:
            keys_to_delete.add(_cache_key("task_list", scope_id, lang, ""))
            if task_id:
                keys_to_delete.add(_cache_key("task_detail", scope_id, lang, str(task_id)))

        idx_key = _cache_index_key(scope_id)
        tracked = cache.get(idx_key)
        if isinstance(tracked, (list, set, tuple)):
            keys_to_delete.update(str(k) for k in tracked)
        keys_to_delete.add(idx_key)

        for key in keys_to_delete:
            cache.delete(key)


class TaskViewSet(viewsets.ModelViewSet):
    """CRUD endpoint for tasks with Redis caching, N+1 prevention, and tenant scoping."""

    queryset = Task.objects.filter(is_active=True)
    serializer_class = TaskSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [
        DjangoFilterBackend,
        filters.OrderingFilter,
    ]
    filterset_class = TaskFilter
    ordering_fields = ["created_at", "updated_at", "status"]

    def get_queryset(self) -> QuerySet[Task]:
        """Return optimized tenant-scoped or user-scoped queryset."""
        base_qs = (
            Task.objects.filter(is_active=True)
            .select_related("user", "organization")
            .prefetch_related("translations")
        )
        organization = getattr(self.request, "organization", None)
        if organization is not None:
            return base_qs.filter(organization=organization)
        return base_qs.filter(user=self.request.user)

    def list(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """List tasks with query-aware, language-scoped Redis caching."""
        scope_id = _scope_id_for_request(request)
        lang = getattr(request, "language", "en")
        q_fingerprint = _query_fingerprint(request)
        cache_key = _cache_key("task_list", scope_id, lang, q_fingerprint)

        cached = cache.get(cache_key)
        if cached is not None:
            record_cache_hit()
            return Response(cached)

        record_cache_miss()
        response = super().list(request, *args, **kwargs)
        cache.set(cache_key, response.data, timeout=CACHE_TTL_LIST)
        register_scope_cache_key(scope_id, cache_key)
        return response

    def retrieve(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """Retrieve a single task with language-scoped Redis caching."""
        scope_id = _scope_id_for_request(request)
        lang = getattr(request, "language", "en")
        task_id = str(kwargs.get("pk", ""))
        cache_key = _cache_key("task_detail", scope_id, lang, task_id)

        cached = cache.get(cache_key)
        if cached is not None:
            record_cache_hit()
            return Response(cached)

        record_cache_miss()
        response = super().retrieve(request, *args, **kwargs)
        cache.set(cache_key, response.data, timeout=CACHE_TTL_DETAIL)
        register_scope_cache_key(scope_id, cache_key)
        return response

    @action(detail=True, methods=["post"], url_path="restore")
    def restore(self, request: Request, pk: str | None = None) -> Response:
        """Restore a soft-deleted task scoped to the user or active organization."""
        base_qs = Task.objects.select_related("user", "organization").prefetch_related(
            "translations"
        )
        organization = getattr(request, "organization", None)
        if organization is not None:
            scoped_qs = base_qs.filter(organization=organization)
        else:
            scoped_qs = base_qs.filter(user=request.user)

        task = get_object_or_404(scoped_qs, pk=pk)

        if task.is_active:
            return Response(
                {"error": "Task is already active."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        task.is_active = True
        task.save(update_fields=["is_active", "updated_at"])
        self._invalidate_for_task(task)
        serializer = self.get_serializer(task)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def perform_create(self, serializer: Any) -> Task:
        """Create task bound to user (and active organization) and invalidate caches."""
        organization = getattr(self.request, "organization", None)
        instance: Task = serializer.save(user=self.request.user, organization=organization)
        self._invalidate_for_task(instance)
        return instance

    def perform_update(self, serializer: Any) -> Task:
        """Update task and invalidate detail + list caches across all languages."""
        instance: Task = serializer.save()
        self._invalidate_for_task(instance)
        return instance

    def perform_destroy(self, instance: Task) -> None:
        """Soft-delete task and invalidate detail + list caches across all languages."""
        instance.delete()
        self._invalidate_for_task(instance)

    def _invalidate_for_task(self, instance: Task) -> None:
        """Invalidate caches for the requesting user, task owner, and task organization."""
        scopes = [str(self.request.user.id), str(instance.user_id)]
        if instance.organization_id:
            scopes.append(f"org:{instance.organization_id}")
        organization = getattr(self.request, "organization", None)
        if organization is not None:
            scopes.append(f"org:{organization.id}")
        invalidate_task_caches_for_scopes(scopes, task_id=str(instance.id))

    def _invalidate_list_cache(self) -> None:
        """Backward-compatible helper to invalidate all list caches for current scope."""
        invalidate_task_caches_for_scopes([_scope_id_for_request(self.request)])

    def _invalidate_detail_cache(self, task_id: Any) -> None:
        """Backward-compatible helper to invalidate detail caches for current scope."""
        invalidate_task_caches_for_scopes(
            [_scope_id_for_request(self.request)],
            task_id=str(task_id),
        )
