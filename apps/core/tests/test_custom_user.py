"""Tests for CustomUser model and manager."""

import pytest
from django.contrib.auth import get_user_model

User = get_user_model()


@pytest.mark.django_db
class TestCustomUserManager:
    def test_create_user_with_email(self):
        user = User.objects.create_user(
            email="test@example.com",
            password="testpass123"
        )
        assert user.email == "test@example.com"
        assert user.is_active is True
        assert user.is_staff is False
        assert user.is_superuser is False
        assert str(user.id)

    def test_create_user_normalizes_email(self):
        user = User.objects.create_user(
            email="Test@EXAMPLE.COM",
            password="testpass123"
        )
        assert user.email == "Test@example.com"

    def test_create_user_without_email_raises(self):
        with pytest.raises(ValueError, match="Email field must be set|Email address is required"):
            User.objects.create_user(email="", password="testpass123")

    def test_create_superuser(self):
        user = User.objects.create_superuser(
            email="admin@example.com",
            password="adminpass123"
        )
        assert user.is_staff is True
        assert user.is_superuser is True

    def test_user_str_returns_email(self):
        user = User.objects.create_user(
            email="str@example.com",
            password="testpass123"
        )
        assert str(user) == "str@example.com"

    def test_get_full_name(self):
        user = User.objects.create_user(
            email="name@example.com",
            password="testpass123",
            first_name="John",
            last_name="Doe"
        )
        assert user.get_full_name() == "John Doe"

    def test_get_full_name_fallback_to_email(self):
        user = User.objects.create_user(
            email="fallback@example.com",
            password="testpass123"
        )
        assert user.get_full_name() == "fallback@example.com"

    def test_get_short_name(self):
        user = User.objects.create_user(
            email="short@example.com",
            password="testpass123",
            first_name="Jane"
        )
        assert user.get_short_name() == "Jane"