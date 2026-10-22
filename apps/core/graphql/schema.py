"""Strawberry GraphQL schema for tasks and organizations.

Provides:
    - ``TaskType``: Translatable task with async-safe field resolution.
    - ``OrganizationType``: Tenant with async-safe computed task/member counts.
    - ``Query``: Read operations with JWT/session auth and tenant scoping.
    - ``Mutation``: Write operations with ownership/RBAC enforcement, input
      sanitization, cache invalidation, and real-time event publishing.

All fields respect the project language resolution chain:
    ``?lang=`` → ``Accept-Language`` → ``en``.
"""

from __future__ import annotations

from typing import Any, List, Optional
from uuid import UUID

from django.http import HttpRequest

import strawberry
from asgiref.sync import sync_to_async
from strawberry.types import Info

from apps.core.events import EventPublisher
from apps.core.middleware import resolve_authenticated_user
from apps.core.models import Organization, OrganizationMember
from apps.core.security import InputValidator
from apps.tasks.models import Task
from apps.tasks.views import invalidate_task_caches_for_scopes

_VALID_STATUSES = frozenset({"pending", "in_progress", "completed", "archived"})
_WRITE_ROLES = frozenset({"contributor", "admin", "owner"})


def _extract_request(info: Info[Any, Any]) -> HttpRequest:
    """Unwrap ``HttpRequest`` from either ``StrawberryDjangoContext`` or raw test context."""
    ctx = info.context
    req = getattr(ctx, "request", ctx)
    return req  # type: ignore[no-any-return]


def _resolve_gql_user_sync(request: HttpRequest) -> Any:
    """Resolve authenticated user from session, test override, or JWT Bearer header."""
    user = resolve_authenticated_user(request)
    if user is not None and getattr(user, "is_authenticated", False):
        return user
    return None


def _task_title_sync(task: Task, lang: str) -> str:
    return task.safe_translation_getter("title", language_code=lang, any_language=True) or ""


def _task_description_sync(task: Task, lang: str) -> str:
    return task.safe_translation_getter("description", language_code=lang, any_language=True) or ""


def _task_translations_sync(task: Task) -> list["TaskTranslationType"]:
    return [
        TaskTranslationType(
            language_code=t.language_code,
            title=t.title,
            description=t.description,
        )
        for t in task.translations.all()
    ]


def _org_task_count_sync(org: Organization) -> int:
    return org.tasks.filter(is_active=True).count()


def _org_member_count_sync(org: Organization) -> int:
    return org.members.count()


@strawberry.type
class TaskTranslationType:
    """A single language translation for a Task."""

    language_code: str
    title: str
    description: str


@strawberry.type
class TaskType:
    """GraphQL representation of a multilingual Task."""

    id: UUID
    status: str
    is_active: bool
    created_at: str

    @strawberry.field
    async def title(self, info: Info[Any, Any]) -> str:
        """Resolve title in the request language without sync-in-async violations."""
        request = _extract_request(info)
        lang = str(getattr(request, "language", "en") or "en")
        return await sync_to_async(_task_title_sync)(self, lang)  # type: ignore[arg-type]

    @strawberry.field
    async def description(self, info: Info[Any, Any]) -> str:
        """Resolve description in the request language without sync-in-async violations."""
        request = _extract_request(info)
        lang = str(getattr(request, "language", "en") or "en")
        return await sync_to_async(_task_description_sync)(self, lang)  # type: ignore[arg-type]

    @strawberry.field
    async def translations(self) -> List[TaskTranslationType]:
        """Return all available translations asynchronously."""
        return await sync_to_async(_task_translations_sync)(self)  # type: ignore[arg-type]


@strawberry.type
class OrganizationType:
    """GraphQL representation of an Organization."""

    id: UUID
    name: str
    slug: str
    plan: str
    is_active: bool
    created_at: str

    @strawberry.field
    async def task_count(self) -> int:
        """Count of active tasks in this organization."""
        return await sync_to_async(_org_task_count_sync)(self)  # type: ignore[arg-type]

    @strawberry.field
    async def member_count(self) -> int:
        """Count of members in this organization."""
        return await sync_to_async(_org_member_count_sync)(self)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Sync DB & Event helpers wrapped via sync_to_async
# ---------------------------------------------------------------------------


def _get_tasks(user: Any, organization_id: UUID | None) -> list[Task]:
    """Return active tasks accessible to ``user``, optionally scoped to ``organization_id``."""
    base_qs = (
        Task.objects.filter(is_active=True)
        .select_related("organization")
        .prefetch_related("translations")
    )
    if organization_id is not None:
        is_member = OrganizationMember.objects.filter(
            organization_id=organization_id,
            organization__is_active=True,
            user=user,
        ).exists()
        if not is_member:
            return []
        return list(base_qs.filter(organization_id=organization_id))
    return list(base_qs.filter(user=user))


def _get_task(user: Any, task_id: UUID) -> Task | None:
    """Return a single active task owned by ``user`` (or in a shared org) or ``None``."""
    try:
        task = (
            Task.objects.select_related("organization")
            .prefetch_related("translations")
            .get(id=task_id, is_active=True)
        )
    except Task.DoesNotExist:
        return None

    if task.user_id == user.id:
        return task
    if (
        task.organization_id
        and OrganizationMember.objects.filter(
            organization_id=task.organization_id,
            organization__is_active=True,
            user=user,
        ).exists()
    ):
        return task
    return None


def _get_organizations(user: Any) -> list[Organization]:
    return list(
        Organization.objects.filter(
            is_active=True,
            members__user=user,
        )
        .distinct()
        .prefetch_related("members", "tasks")
    )


def _get_organization(user: Any, org_id: UUID) -> Organization | None:
    try:
        return Organization.objects.get(
            id=org_id,
            is_active=True,
            members__user=user,
        )
    except Organization.DoesNotExist:
        return None


def _create_task_sync(
    user: Any,
    title: str,
    description: str,
    status: str,
    lang: str,
) -> tuple[Task, Organization | None] | None:
    """Validate, authorize, and create a Task and its translation synchronously."""
    if status not in _VALID_STATUSES:
        return None

    is_bad_title, _ = InputValidator.detect_injection(title)
    is_bad_desc, _ = InputValidator.detect_injection(description)
    if is_bad_title or is_bad_desc:
        return None

    try:
        clean_title = InputValidator.sanitize_string(title, max_length=255)
        clean_desc = InputValidator.sanitize_string(description, max_length=10000)
    except ValueError:
        return None

    if not clean_title:
        return None

    membership = (
        user.organization_memberships.select_related("organization")
        .filter(organization__is_active=True)
        .first()
    )
    organization: Organization | None = None
    if membership is not None:
        if membership.role not in _WRITE_ROLES:
            return None
        if membership.organization.tasks.filter(is_active=True).count() >= (
            membership.organization.max_tasks
        ):
            return None
        organization = membership.organization

    task = Task.objects.create(user=user, organization=organization, status=status)
    target_lang = lang if lang in ("en", "es", "fr") else "en"
    task.set_current_language(target_lang)
    task.title = clean_title
    task.description = clean_desc
    task.save()

    scopes = [str(user.id)]
    if organization is not None:
        scopes.append(f"org:{organization.id}")
    invalidate_task_caches_for_scopes(scopes, task_id=str(task.id))

    publisher = EventPublisher()
    publisher.publish_task_event(
        str(organization.id) if organization else "global",
        "created",
        {"id": str(task.id), "status": task.status, "user_id": str(user.id)},
    )
    refetched = (
        Task.objects.select_related("organization").prefetch_related("translations").get(id=task.id)
    )
    return refetched, organization


def _update_task_status_sync(user: Any, task_id: UUID, new_status: str) -> Task | None:
    """Authorize ownership/tenant RBAC and update task status; returns None if forbidden."""
    if new_status not in _VALID_STATUSES:
        return None

    try:
        task = (
            Task.objects.select_related("organization")
            .prefetch_related("translations")
            .get(id=task_id, is_active=True)
        )
    except Task.DoesNotExist:
        return None

    # Enforce strict ownership or write-role membership in the task's active organization
    is_authorized = task.user_id == user.id
    if not is_authorized and task.organization_id:
        is_authorized = OrganizationMember.objects.filter(
            organization_id=task.organization_id,
            organization__is_active=True,
            user=user,
            role__in=_WRITE_ROLES,
        ).exists()

    if not is_authorized:
        return None

    task.status = new_status
    task.save(update_fields=["status", "updated_at"])

    scopes = [str(user.id), str(task.user_id)]
    if task.organization_id:
        scopes.append(f"org:{task.organization_id}")
    invalidate_task_caches_for_scopes(scopes, task_id=str(task.id))

    publisher = EventPublisher()
    publisher.publish_task_event(
        str(task.organization_id) if task.organization_id else "global",
        "updated",
        {"id": str(task.id), "status": task.status, "user_id": str(user.id)},
    )
    return task


@strawberry.type
class Query:
    """Read operations for tasks and organizations."""

    @strawberry.field
    async def tasks(
        self,
        info: Info[Any, Any],
        organization_id: Optional[UUID] = None,
    ) -> List[TaskType]:
        """List tasks scoped to the authenticated user or verified organization."""
        request = _extract_request(info)
        user = await sync_to_async(_resolve_gql_user_sync)(request)
        if user is None:
            return []
        result = await sync_to_async(_get_tasks)(user, organization_id)
        return result  # type: ignore[return-value]

    @strawberry.field
    async def task(self, info: Info[Any, Any], id: UUID) -> Optional[TaskType]:
        """Retrieve a single task by ID if authorized."""
        request = _extract_request(info)
        user = await sync_to_async(_resolve_gql_user_sync)(request)
        if user is None:
            return None
        result = await sync_to_async(_get_task)(user, id)
        return result  # type: ignore[return-value]

    @strawberry.field
    async def organizations(self, info: Info[Any, Any]) -> List[OrganizationType]:
        """List organizations the user is an active member of."""
        request = _extract_request(info)
        user = await sync_to_async(_resolve_gql_user_sync)(request)
        if user is None:
            return []
        result = await sync_to_async(_get_organizations)(user)
        return result  # type: ignore[return-value]

    @strawberry.field
    async def organization(self, info: Info[Any, Any], id: UUID) -> Optional[OrganizationType]:
        """Retrieve a single organization by ID if the user is a member."""
        request = _extract_request(info)
        user = await sync_to_async(_resolve_gql_user_sync)(request)
        if user is None:
            return None
        result = await sync_to_async(_get_organization)(user, id)
        return result  # type: ignore[return-value]


@strawberry.type
class Mutation:
    """Write operations with authorization, cache invalidation, and event publishing."""

    @strawberry.mutation
    async def create_task(
        self,
        info: Info[Any, Any],
        title: str,
        description: str,
        status: str = "pending",
    ) -> Optional[TaskType]:
        """Create a new task for the authenticated user."""
        request = _extract_request(info)
        user = await sync_to_async(_resolve_gql_user_sync)(request)
        if user is None:
            return None

        lang = str(getattr(request, "language", "en") or "en")
        created = await sync_to_async(_create_task_sync)(user, title, description, status, lang)
        if created is None:
            return None
        task, _organization = created
        return task  # type: ignore[return-value]

    @strawberry.mutation
    async def update_task_status(
        self,
        info: Info[Any, Any],
        task_id: UUID,
        new_status: str,
    ) -> Optional[TaskType]:
        """Update the status of an existing task if owned or authorized in its org."""
        request = _extract_request(info)
        user = await sync_to_async(_resolve_gql_user_sync)(request)
        if user is None:
            return None

        task = await sync_to_async(_update_task_status_sync)(user, task_id, new_status)
        return task  # type: ignore[return-value]


schema = strawberry.Schema(query=Query, mutation=Mutation)
