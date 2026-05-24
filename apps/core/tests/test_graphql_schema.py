"""Tests for GraphQL schema resolvers."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.test import RequestFactory

from apps.core.graphql.schema import Mutation, Query, TaskType
from apps.core.models import Organization, OrganizationMember
from apps.tasks.models import Task

User = get_user_model()


@pytest.fixture
def rf() -> RequestFactory:
    return RequestFactory()


def _info(request):
    return SimpleNamespace(context=request)


@pytest.mark.django_db
def test_tasktype_resolves_title_description_and_translations(rf):
    user = User.objects.create_user(email="graphql-task@example.com", password="pass1234")
    task = Task.objects.create(user=user, status="pending")
    task.set_current_language("en")
    task.title = "Hello"
    task.description = "English description"
    task.save()
    task.set_current_language("es")
    task.title = "Hola"
    task.description = "Descripción"
    task.save()

    request = rf.get("/graphql/")
    request.language = "es"
    info = _info(request)

    assert TaskType.title(task, info) == "Hola"
    assert TaskType.description(task, info) == "Descripción"
    translations = TaskType.translations(task)
    assert {t.language_code for t in translations} == {"en", "es"}


@pytest.mark.django_db
def test_query_tasks_filters_by_membership_and_organization(rf):
    query = Query()
    user = User.objects.create_user(email="graphql-user@example.com", password="pass1234")
    other = User.objects.create_user(email="graphql-other@example.com", password="pass1234")
    org_a = Organization.objects.create(name="Org A", slug="graphql-org-a")
    org_b = Organization.objects.create(name="Org B", slug="graphql-org-b")
    OrganizationMember.objects.create(organization=org_a, user=user, role="owner")
    OrganizationMember.objects.create(organization=org_b, user=other, role="owner")

    task_a = Task.objects.create(user=user, organization=org_a, status="pending", is_active=True)
    task_b = Task.objects.create(user=other, organization=org_b, status="pending", is_active=True)
    task_b.delete()

    request = rf.get("/graphql/")
    request.user = user
    result = query.tasks(_info(request))
    assert [t.id for t in result] == [task_a.id]

    result_filtered = query.tasks(_info(request), organization_id=org_a.id)
    assert [t.id for t in result_filtered] == [task_a.id]


def test_query_tasks_returns_empty_for_anonymous(rf):
    request = rf.get("/graphql/")
    request.user = AnonymousUser()
    assert Query().tasks(_info(request)) == []


@pytest.mark.django_db
def test_query_task_returns_none_for_missing_or_unauthorized(rf):
    user = User.objects.create_user(email="graphql-single@example.com", password="pass1234")
    org = Organization.objects.create(name="Org Q", slug="graphql-org-q")
    OrganizationMember.objects.create(organization=org, user=user, role="owner")
    task = Task.objects.create(user=user, organization=org, status="pending", is_active=True)

    anon_req = rf.get("/graphql/")
    anon_req.user = AnonymousUser()
    assert Query().task(_info(anon_req), id=task.id) is None

    auth_req = rf.get("/graphql/")
    auth_req.user = user
    assert Query().task(_info(auth_req), id=task.id) is not None
    assert Query().task(_info(auth_req), id=uuid4()) is None


@pytest.mark.django_db
def test_query_organizations_and_organization_lookup(rf):
    user = User.objects.create_user(email="graphql-org-user@example.com", password="pass1234")
    org = Organization.objects.create(name="Org Z", slug="graphql-org-z")
    OrganizationMember.objects.create(organization=org, user=user, role="admin")

    request = rf.get("/graphql/")
    request.user = user
    query = Query()

    orgs = query.organizations(_info(request))
    assert len(orgs) == 1
    assert orgs[0].id == org.id

    found = query.organization(_info(request), id=org.id)
    assert found is not None
    missing = query.organization(_info(request), id=uuid4())
    assert missing is None


def test_query_organizations_returns_empty_for_anonymous(rf):
    request = rf.get("/graphql/")
    request.user = AnonymousUser()
    assert Query().organizations(_info(request)) == []
    assert Query().organization(_info(request), id=uuid4()) is None


@pytest.mark.django_db
def test_mutation_create_task_returns_none_for_anonymous(rf):
    request = rf.post("/graphql/")
    request.user = AnonymousUser()
    result = Mutation().create_task(_info(request), title="A", description="B")
    assert result is None


@pytest.mark.django_db
def test_mutation_create_task_publishes_event_with_org_scope(rf):
    user = User.objects.create_user(email="graphql-mutation@example.com", password="pass1234")
    org = Organization.objects.create(name="Org M", slug="graphql-org-m")
    OrganizationMember.objects.create(organization=org, user=user, role="owner")
    request = rf.post("/graphql/")
    request.user = user

    with patch("apps.core.graphql.schema.EventPublisher") as publisher_cls:
        task = Mutation().create_task(_info(request), title="New Title", description="New Desc")

    assert task is not None
    task.set_current_language("en")
    assert task.title == "New Title"
    assert task.description == "New Desc"
    publisher_cls.return_value.publish_task_event.assert_called_once()
    org_arg = publisher_cls.return_value.publish_task_event.call_args.args[0]
    assert org_arg == str(org.id)


@pytest.mark.django_db
def test_mutation_create_task_without_membership_uses_global_channel(rf):
    user = User.objects.create_user(email="graphql-global@example.com", password="pass1234")
    request = rf.post("/graphql/")
    request.user = user

    with patch("apps.core.graphql.schema.EventPublisher") as publisher_cls:
        task = Mutation().create_task(_info(request), title="T", description="D")

    assert task is not None
    org_arg = publisher_cls.return_value.publish_task_event.call_args.args[0]
    assert org_arg == "global"
