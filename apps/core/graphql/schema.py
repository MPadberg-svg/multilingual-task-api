"""Strawberry GraphQL schema for tasks and organizations.

Provides:
    - ``TaskType``: Translatable task with lazy title/description resolution.
    - ``OrganizationType``: Tenant with computed task/member counts.
    - ``Query``: Read operations with tenant scoping and auth.
    - ``Mutation``: Write operations with event publishing.

All fields respect the project language resolution chain:
    ``?lang=`` → ``Accept-Language`` → ``en``.

All resolver functions are wrapped with ``sync_to_async`` so the schema
can be executed from an async context (Strawberry's ASGI view) without
triggering Django's SynchronousOnlyOperation guard.
"""

from typing import List, Optional
from uuid import UUID

import strawberry
from asgiref.sync import sync_to_async
from strawberry.types import Info

from apps.core.events import EventPublisher
from apps.core.models import Organization
from apps.tasks.models import Task

# ---------------------------------------------------------------------------
# Strawberry types
# ---------------------------------------------------------------------------

_VALID_STATUSES = {"pending", "in_progress", "completed", "archived"}


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
    def title(self, info: Info) -> str:
        """Resolve title in the request language."""
        request = info.context
        lang = getattr(request, "language", "en")
        return self.safe_translation_getter("title", language_code=lang, any_language=True) or ""

    @strawberry.field
    def description(self, info: Info) -> str:
        """Resolve description in the request language."""
        request = info.context
        lang = getattr(request, "language", "en")
        return (
            self.safe_translation_getter("description", language_code=lang, any_language=True) or ""
        )

    @strawberry.field
    def translations(self) -> List[TaskTranslationType]:
        """Return all translations."""
        return [
            TaskTranslationType(
                language_code=t.language_code,
                title=t.title,
                description=t.description,
            )
            for t in self.get_translations()
        ]


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
    def task_count(self) -> int:
        """Count of active tasks in this organization."""
        return self.tasks.filter(is_active=True).count()

    @strawberry.field
    def member_count(self) -> int:
        """Count of members in this organization."""
        return self.members.count()


# ---------------------------------------------------------------------------
# Helper: sync DB accessors for use with sync_to_async
# ---------------------------------------------------------------------------

def _get_tasks(user, organization_id):
    """Return active tasks owned by *user*, optionally filtered by *organization_id*.

    Filters by task ownership (``user=user``) rather than org membership so
    tasks without an organization are still visible to their creator.
    """
    qs = (
        Task.objects.filter(is_active=True, user=user)
        .select_related("organization")
        .prefetch_related("translations")
    )
    if organization_id:
        qs = qs.filter(organization_id=organization_id)
    return list(qs)


def _get_task(user, task_id):
    """Return a single task owned by *user* or ``None``.

    Enforces ownership by filtering ``user=user`` so a task is only
    accessible to its creator, regardless of org membership.
    """
    try:
        return Task.objects.get(id=task_id, is_active=True, user=user)
    except Task.DoesNotExist:
        return None


def _get_organizations(user):
    return list(
        Organization.objects.filter(
            is_active=True,
            members__user=user,
        ).prefetch_related("members", "tasks")
    )


def _get_organization(user, org_id):
    try:
        return Organization.objects.get(
            id=org_id,
            is_active=True,
            members__user=user,
        )
    except Organization.DoesNotExist:
        return None


def _create_task_sync(user, title, description, status):
    """Create a Task and its English translation synchronously."""
    membership = user.organization_memberships.select_related("organization").first()
    organization = membership.organization if membership else None

    task = Task.objects.create(user=user, organization=organization, status=status)
    task.set_current_language("en")
    task.title = title
    task.description = description
    task.save()
    return task, organization


def _update_task_status_sync(user, task_id, new_status):
    """Update task status; returns updated task or None."""
    if new_status not in _VALID_STATUSES:
        return None
    try:
        task = Task.objects.get(id=task_id, is_active=True)
        task.status = new_status
        task.save(update_fields=["status", "updated_at"])
        return task
    except Task.DoesNotExist:
        return None


# ---------------------------------------------------------------------------
# Query
# ---------------------------------------------------------------------------


@strawberry.type
class Query:
    """Read operations for tasks and organizations."""

    @strawberry.field
    async def tasks(
        self, info: Info, organization_id: Optional[UUID] = None
    ) -> List[TaskType]:
        """List tasks scoped to the authenticated user's organizations."""
        request = info.context
        if not request.user.is_authenticated:
            return []
        return await sync_to_async(_get_tasks)(request.user, organization_id)

    @strawberry.field
    async def task(self, info: Info, id: UUID) -> Optional[TaskType]:
        """Retrieve a single task by ID, scoped to user's organizations."""
        request = info.context
        if not request.user.is_authenticated:
            return None
        return await sync_to_async(_get_task)(request.user, id)

    @strawberry.field
    async def organizations(self, info: Info) -> List[OrganizationType]:
        """List organizations the user is a member of."""
        request = info.context
        if not request.user.is_authenticated:
            return []
        return await sync_to_async(_get_organizations)(request.user)

    @strawberry.field
    async def organization(self, info: Info, id: UUID) -> Optional[OrganizationType]:
        """Retrieve a single organization by ID if user is a member."""
        request = info.context
        if not request.user.is_authenticated:
            return None
        return await sync_to_async(_get_organization)(request.user, id)


# ---------------------------------------------------------------------------
# Mutation
# ---------------------------------------------------------------------------


@strawberry.type
class Mutation:
    """Write operations with event publishing."""

    @strawberry.mutation
    async def create_task(
        self, info: Info, title: str, description: str, status: str = "pending"
    ) -> Optional[TaskType]:
        """Create a new task for the authenticated user."""
        request = info.context
        if not request.user.is_authenticated:
            return None

        task, organization = await sync_to_async(_create_task_sync)(
            request.user, title, description, status
        )

        publisher = EventPublisher()
        publisher.publish_task_event(
            str(organization.id) if organization else "global",
            "created",
            {"id": str(task.id), "status": task.status, "user_id": str(request.user.id)},
        )
        return task

    @strawberry.mutation
    async def update_task_status(
        self, info: Info, task_id: UUID, new_status: str
    ) -> Optional[TaskType]:
        """Update the status of an existing task.

        Returns the updated task, or ``None`` if the task is not found,
        does not belong to the requesting user, or *new_status* is invalid.
        """
        request = info.context
        if not request.user.is_authenticated:
            return None

        task = await sync_to_async(_update_task_status_sync)(
            request.user, task_id, new_status
        )
        if task is None:
            return None

        publisher = EventPublisher()
        publisher.publish_task_event(
            str(task.organization_id) if task.organization_id else "global",
            "updated",
            {"id": str(task.id), "status": task.status, "user_id": str(request.user.id)},
        )
        return task


schema = strawberry.Schema(query=Query, mutation=Mutation)
