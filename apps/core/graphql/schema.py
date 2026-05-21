"""Strawberry GraphQL schema for tasks and organizations.

Provides:
    - ``TaskType``: Translatable task with lazy title/description resolution.
    - ``OrganizationType``: Tenant with computed task/member counts.
    - ``Query``: Read operations with tenant scoping and auth.
    - ``Mutation``: Write operations with event publishing.

All fields respect the project language resolution chain:
    ``?lang=`` → ``Accept-Language`` → ``en``.
"""

from typing import List, Optional
from uuid import UUID

import strawberry
from strawberry.types import Info

from apps.core.events import EventPublisher
from apps.core.models import Organization
from apps.tasks.models import Task


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
        request = info.context.get("request")
        lang = getattr(request, "language", "en") if request else "en"
        return self.safe_translation_getter("title", language_code=lang, any_language=True) or ""

    @strawberry.field
    def description(self, info: Info) -> str:
        """Resolve description in the request language."""
        request = info.context.get("request")
        lang = getattr(request, "language", "en") if request else "en"
        return self.safe_translation_getter("description", language_code=lang, any_language=True) or ""

    @strawberry.field
    def translations(self) -> List["TaskTranslationType"]:
        """Return all translations."""
        return [
            TaskTranslationType(
                language_code=t.language_code,
                title=t.title,
                description=t.description,
            )
            for t in self.translations.all()
        ]


@strawberry.type
class TaskTranslationType:
    """A single language translation for a Task."""

    language_code: str
    title: str
    description: str


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


@strawberry.type
class Query:
    """Read operations for tasks and organizations."""

    @strawberry.field
    def tasks(self, info: Info, organization_id: Optional[UUID] = None) -> List[TaskType]:
        """List tasks scoped to the authenticated user's organizations."""
        request = info.context.get("request")
        if not request or not hasattr(request, "user") or not request.user.is_authenticated:
            return []

        qs = Task.objects.filter(
            is_active=True,
            organization__members__user=request.user,
        ).select_related("organization").prefetch_related("translations")

        if organization_id:
            qs = qs.filter(organization_id=organization_id)

        return list(qs)

    @strawberry.field
    def task(self, info: Info, id: UUID) -> Optional[TaskType]:
        """Retrieve a single task by ID, scoped to user's organizations."""
        request = info.context.get("request")
        if not request or not hasattr(request, "user") or not request.user.is_authenticated:
            return None

        try:
            return Task.objects.get(
                id=id,
                is_active=True,
                organization__members__user=request.user,
            )
        except Task.DoesNotExist:
            return None

    @strawberry.field
    def organizations(self, info: Info) -> List[OrganizationType]:
        """List organizations the user is a member of."""
        request = info.context.get("request")
        if not request or not hasattr(request, "user") or not request.user.is_authenticated:
            return []

        return list(
            Organization.objects.filter(
                is_active=True,
                members__user=request.user,
            ).prefetch_related("members", "tasks")
        )

    @strawberry.field
    def organization(self, info: Info, id: UUID) -> Optional[OrganizationType]:
        """Retrieve a single organization by ID if user is a member."""
        request = info.context.get("request")
        if not request or not hasattr(request, "user") or not request.user.is_authenticated:
            return None

        try:
            return Organization.objects.get(
                id=id,
                is_active=True,
                members__user=request.user,
            )
        except Organization.DoesNotExist:
            return None


@strawberry.type
class Mutation:
    """Write operations with event publishing."""

    @strawberry.mutation
    def create_task(self, info: Info, title: str, description: str, status: str = "pending") -> Optional[TaskType]:
        """Create a new task for the authenticated user."""
        request = info.context.get("request")
        if not request or not hasattr(request, "user") or not request.user.is_authenticated:
            return None

        user = request.user

        # Get user's primary organization
        membership = user.organization_memberships.select_related("organization").first()
        organization = membership.organization if membership else None

        task = Task.objects.create(
            user=user,
            organization=organization,
            status=status,
        )
        task.set_current_language("en")
        task.title = title
        task.description = description
        task.save()

        publisher = EventPublisher()
        publisher.publish_task_event(
            str(organization.id) if organization else "global",
            "created",
            {"id": str(task.id), "status": task.status, "user_id": str(user.id)},
        )
        return task


schema = strawberry.Schema(query=Query, mutation=Mutation)