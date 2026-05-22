"""Shared pytest fixtures for the entire test suite."""

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import AccessToken

from apps.core.models import Organization, OrganizationMember
from apps.tasks.models import Task

User = get_user_model()


@pytest.fixture
def user(db):
    """Create a standard authenticated user."""
    return User.objects.create_user(
        email="test@example.com",
        password="testpass123",
        first_name="Test",
        last_name="User",
    )


@pytest.fixture
def admin_user(db):
    """Create a staff/superuser."""
    return User.objects.create_superuser(
        email="admin@example.com",
        password="adminpass123",
    )


@pytest.fixture
def api_client():
    """Unauthenticated DRF APIClient."""
    return APIClient()


@pytest.fixture
def auth_client(user):
    """DRF APIClient authenticated as `user`."""
    client = APIClient()
    client.force_authenticate(user=user)
    return client


@pytest.fixture
def jwt_token(user):
    """Generate a valid JWT access token for `user`."""
    return str(AccessToken.for_user(user))


@pytest.fixture
def organization(db, user):
    """Create an Organization with `user` as owner."""
    org = Organization.objects.create(
        name="Test Org",
        slug="test-org",
        plan="starter",
    )
    OrganizationMember.objects.create(
        organization=org,
        user=user,
        role="owner",
    )
    return org


@pytest.fixture
def task(db, user):
    """Create a simple Task with English translation."""
    t = Task.objects.create(user=user, status="pending")
    t.set_current_language("en")
    t.title = "Test Task Title"
    t.description = "Test task description."
    t.save()
    return t


@pytest.fixture
def multilingual_task(db, user):
    """Create a Task with EN/ES/FR translations."""
    t = Task.objects.create(user=user, status="pending")

    t.set_current_language("en")
    t.title = "English Title"
    t.description = "English description."
    t.save()

    t.set_current_language("es")
    t.title = "Título en Español"
    t.description = "Descripción en español."
    t.save()

    t.set_current_language("fr")
    t.title = "Titre en Français"
    t.description = "Description en français."
    t.save()

    return t