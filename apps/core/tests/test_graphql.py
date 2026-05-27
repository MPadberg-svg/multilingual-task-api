"""Tests for Strawberry GraphQL schema — queries and mutations."""

import pytest
from django.contrib.auth import get_user_model
from django.test import AsyncRequestFactory

from apps.core.graphql.schema import schema
from apps.tasks.models import Task

User = get_user_model()


async def _execute(query: str, user=None):
    """Execute a GraphQL query against the schema directly."""
    factory = AsyncRequestFactory()
    request = factory.post(
        "/graphql/",
        data=query,
        content_type="application/json",
    )
    if user:
        request.user = user
    else:
        from django.contrib.auth.models import AnonymousUser
        request.user = AnonymousUser()
    result = await schema.execute(query, context_value=request)
    return result


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
class TestGraphQLQueries:

    async def test_tasks_query_returns_empty_for_anonymous(self):
        """Unauthenticated query must return empty list, not an error."""
        result = await _execute("{ tasks { id status } }")
        assert result.errors is None
        assert result.data["tasks"] == []

    async def test_task_query_returns_none_for_anonymous(self):
        """Single task query must return None for unauthenticated user."""
        from uuid import uuid4
        result = await _execute(f'{{ task(id: "{uuid4()}") {{ id }} }}')
        assert result.errors is None
        assert result.data["task"] is None

    async def test_tasks_query_returns_users_tasks(self):
        """Authenticated user sees their own tasks."""
        from asgiref.sync import sync_to_async

        user = await sync_to_async(User.objects.create_user)(
            email="gql_query@example.com", password="pass"
        )

        def _create_task_with_title(u):
            t = Task.objects.create(user=u, status="pending")
            t.set_current_language("en")
            t.title = "GraphQL Test Task"
            t.save()
            return t

        _ = await sync_to_async(_create_task_with_title)(user)

        result = await _execute("{ tasks { id status } }", user=user)
        assert result.errors is None
        assert len(result.data["tasks"]) == 1
        assert result.data["tasks"][0]["status"] == "pending"

    async def test_tasks_query_excludes_soft_deleted(self):
        """Soft-deleted tasks must not appear in GraphQL results."""
        from asgiref.sync import sync_to_async

        user = await sync_to_async(User.objects.create_user)(
            email="gql_deleted@example.com", password="pass"
        )
        task = await sync_to_async(Task.objects.create)(
            user=user, status="pending", is_active=False
        )

        result = await _execute("{ tasks { id } }", user=user)
        assert result.errors is None
        task_ids = [t["id"] for t in result.data["tasks"]]
        assert str(task.id) not in task_ids

    async def test_task_query_by_id_returns_correct_task(self):
        """task(id:) must return the correct task for its owner."""
        from asgiref.sync import sync_to_async

        user = await sync_to_async(User.objects.create_user)(
            email="gql_detail@example.com", password="pass"
        )
        task = await sync_to_async(Task.objects.create)(user=user, status="completed")

        result = await _execute(
            f'{{ task(id: "{task.id}") {{ id status }} }}',
            user=user,
        )
        assert result.errors is None
        assert result.data["task"]["status"] == "completed"

    async def test_task_query_returns_none_for_wrong_owner(self):
        """task(id:) must not expose another user's task."""
        from asgiref.sync import sync_to_async

        owner = await sync_to_async(User.objects.create_user)(
            email="gql_owner@example.com", password="pass"
        )
        attacker = await sync_to_async(User.objects.create_user)(
            email="gql_attacker@example.com", password="pass"
        )
        task = await sync_to_async(Task.objects.create)(user=owner, status="pending")

        result = await _execute(
            f'{{ task(id: "{task.id}") {{ id }} }}',
            user=attacker,
        )
        assert result.errors is None
        assert result.data["task"] is None


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
class TestGraphQLMutations:

    async def test_update_task_status_succeeds(self):
        """updateTaskStatus must change the task status."""
        from asgiref.sync import sync_to_async

        user = await sync_to_async(User.objects.create_user)(
            email="gql_mut@example.com", password="pass"
        )
        task = await sync_to_async(Task.objects.create)(user=user, status="pending")

        mutation = f"""
            mutation {{
                updateTaskStatus(taskId: "{task.id}", newStatus: "completed") {{
                    id
                    status
                }}
            }}
        """
        result = await _execute(mutation, user=user)
        assert result.errors is None
        assert result.data["updateTaskStatus"]["status"] == "completed"

    async def test_update_task_status_invalid_returns_none(self):
        """Invalid status value must return None, not raise an error."""
        from asgiref.sync import sync_to_async

        user = await sync_to_async(User.objects.create_user)(
            email="gql_invalid@example.com", password="pass"
        )
        task = await sync_to_async(Task.objects.create)(user=user, status="pending")

        mutation = f"""
            mutation {{
                updateTaskStatus(taskId: "{task.id}", newStatus: "not_a_real_status") {{
                    id
                }}
            }}
        """
        result = await _execute(mutation, user=user)
        assert result.errors is None
        assert result.data["updateTaskStatus"] is None

    async def test_update_task_status_unauthenticated_returns_none(self):
        """Unauthenticated mutation must return None, not raise."""
        from uuid import uuid4

        mutation = f"""
            mutation {{
                updateTaskStatus(taskId: "{uuid4()}", newStatus: "completed") {{
                    id
                }}
            }}
        """
        result = await _execute(mutation, user=None)
        assert result.errors is None
        assert result.data["updateTaskStatus"] is None
