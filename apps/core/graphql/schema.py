"""Strawberry GraphQL schema for tasks and organizations.

Provides:
    - ``TaskType``: Translatable task with lazy title/description resolution.
    - ``OrganizationType``: Tenant with computed task/member counts.
    - ``Query``: Read operations with tenant scoping.
    - ``Mutation``: Write operations with event publishing.

All fields respect the project language resolution chain:
    ``?lang=`` → ``Accept-Language`` → ``en``.
"""

from typing import List, Optional
from uuid import UUID

import django.utils.timezone as timezone
import strawberry
from strawberry.types import Info

from apps.core.events import EventPublisher
from apps.core.models import Organization
from apps.tasks.models import Task


@strawberry.type
class TaskType:
    """GraphQL representation of a multilingual Task.

    Attributes:
        id: UUID primary key.
        status: Workflow state.
        is_active: Soft-delete flag.
        created_at: ISO timestamp string.
    """

    id: UUID
    status: str
    is_active: bool
    created_at: str

    @strawberry.field
    def title(self, info: Info, language: Optional[str] = None) -> str:
        """Resolve title in requested or context language.

        Falls back to ``en`` then ``'Untitled'``.

        Args:
            info: Strawberry execution context.
            language: Override language code.

        Returns:
            Localised title string.
        """
        lang = language or info.context.request.lang
        task = Task.objects.get(id=self.id)
        task.set_current_language(lang)
        return (
            task.title
            or task.safe_translation_getter("title", language_code="en")
            or "Untitled"
        )

    @strawberry.field
    def description(self, info: Info, language: Optional[str] = None) -> str:
        """Resolve description in requested or context language.

        Args:
            info: Strawberry execution context.
            language: Override language code.

        Returns:
            Localised description string.
        """
        lang = language or info.context.request.lang
        task = Task.objects.get(id=self.id)
        task.set_current_language(lang)
        return task.description or ""

    @strawberry.field
    def translations(self, info: Info) -> List[dict]:
        """Return all translation records for the task.

        Args:
            info: Strawberry execution context.

        Returns:
            List of dicts with ``language``, ``title``, ``description``.
        """
        task = Task.objects.get(id=self.id)
        return [
            {
                "language": t.language_code,
                "title": t.title,
                "description": t.description,
            }
            for t in task.translations.all()
        ]


@strawberry.type
class OrganizationType:
    """GraphQL representation of an Organization tenant.

    Attributes:
        id: UUID primary key.
        name: Human-readable name.
        slug: URL-friendly identifier.
        plan: Billing tier.
    """

    id: UUID
    name: str
    slug: str
    plan: str

    @strawberry.field
    def task_count(self, info: Info) -> int:
        """Count active tasks scoped to this organization.

        Args:
            info: Strawberry execution context.

        Returns:
            Active task count.
        """
        return Task.objects.filter(organization_id=self.id, is_active=True).count()

    @strawberry.field
    def member_count(self, info: Info) -> int:
        """Count members of this organization.

        Args:
            info: Strawberry execution context.

        Returns:
            Member count.
        """
        from apps.core.models import OrganizationMember

        return OrganizationMember.objects.filter(organization_id=self.id).count()


@strawberry.type
class Query:
    """GraphQL read operations."""

    @strawberry.field
    def task(self, info: Info, id: UUID) -> Optional[TaskType]:
        """Fetch a single active task by UUID.

        Args:
            info: Strawberry execution context.
            id: Task UUID.

        Returns:
            ``TaskType`` or ``None`` if not found.
        """
        try:
            t = Task.objects.get(id=id, is_active=True)
            return TaskType(
                id=t.id,
                status=t.status,
                is_active=t.is_active,
                created_at=str(t.created_at),
            )
        except Task.DoesNotExist:
            return None

    @strawberry.field
    def tasks(
        self,
        info: Info,
        status: Optional[str] = None,
        limit: int = 20,
        offset: int = 0,
    ) -> List[TaskType]:
        """List active tasks with optional filtering and tenant scoping.

        Args:
            info: Strawberry execution context.
            status: Filter by workflow state.
            limit: Maximum results (default 20).
            offset: Pagination offset.

        Returns:
            List of ``TaskType`` instances.
        """
        qs = Task.objects.filter(is_active=True)
        if status:
            qs = qs.filter(status=status)
        if info.context.request.organization:
            qs = qs.filter(organization=info.context.request.organization)
        qs = qs[offset : offset + limit]
        return [
            TaskType(
                id=t.id,
                status=t.status,
                is_active=t.is_active,
                created_at=str(t.created_at),
            )
            for t in qs
        ]

    @strawberry.field
    def organization(self, info: Info, slug: str) -> Optional[OrganizationType]:
        """Fetch an active organization by slug.

        Args:
            info: Strawberry execution context.
            slug: Organization slug.

        Returns:
            ``OrganizationType`` or ``None`` if not found.
        """
        try:
            org = Organization.objects.get(slug=slug, is_active=True)
            return OrganizationType(
                id=org.id,
                name=org.name,
                slug=org.slug,
                plan=org.plan,
            )
        except Organization.DoesNotExist:
            return None


@strawberry.type
class Mutation:
    """GraphQL write operations with event publishing."""

    @strawberry.mutation
    def create_task(
        self,
        info: Info,
        title: str,
        description: str,
        status: str = "draft",
    ) -> TaskType:
        """Create a new multilingual task.

        Args:
            info: Strawberry execution context.
            title: Task title (stored in context language).
            description: Task description.
            status: Initial workflow state (default ``draft``).

        Returns:
            Created ``TaskType``.
        """
        task = Task.objects.create(
            user=info.context.request.user,
            organization=info.context.request.organization,
            status=status,
        )
        lang = info.context.request.lang or "en"
        task.set_current_language(lang)
        task.title = title
        task.description = description
        task.save()

        EventPublisher().publish_task_event(
            str(task.organization.id) if task.organization else "global",
            "created",
            {"id": str(task.id), "title": title},
        )
        return TaskType(
            id=task.id,
            status=task.status,
            is_active=task.is_active,
            created_at=str(task.created_at),
        )

    @strawberry.mutation
    def update_task_status(
        self,
        info: Info,
        id: UUID,
        status: str,
    ) -> Optional[TaskType]:
        """Update a task's status.

        Args:
            info: Strawberry execution context.
            id: Task UUID.
            status: New workflow state.

        Returns:
            Updated ``TaskType`` or ``None`` if not found.
        """
        try:
            task = Task.objects.get(id=id)
            task.status = status
            task.save()

            EventPublisher().publish_task_event(
                str(task.organization.id) if task.organization else "global",
                "updated",
                {"id": str(task.id), "status": status},
            )
            return TaskType(
                id=task.id,
                status=task.status,
                is_active=task.is_active,
                created_at=str(task.created_at),
            )
        except Task.DoesNotExist:
            return None


schema = strawberry.Schema(query=Query, mutation=Mutation)