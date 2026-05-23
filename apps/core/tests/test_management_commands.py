"""Tests for Django management commands."""

from io import StringIO

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError

import pytest

User = get_user_model()


@pytest.mark.django_db
class TestCreateSuperuserIfMissing:
    """Tests for create_superuser_if_missing command."""

    def test_creates_superuser_when_none_exists(self):
        """Command should create superuser if none exists."""
        out = StringIO()
        call_command(
            "create_superuser_if_missing",
            "--email",
            "admin@test.com",
            "--password",
            "adminpass123",
            stdout=out,
        )
        output = out.getvalue()
        assert "Superuser created" in output
        assert User.objects.filter(is_superuser=True).exists()

    def test_skips_when_superuser_already_exists(self):
        """Command should be idempotent — skip if superuser exists."""
        User.objects.create_superuser(
            email="existing@admin.com",
            password="existingpass123",
        )
        out = StringIO()
        call_command(
            "create_superuser_if_missing",
            "--email",
            "new@test.com",
            "--password",
            "newpass123",
            stdout=out,
        )
        output = out.getvalue()
        assert "already exists" in output
        assert User.objects.filter(is_superuser=True).count() == 1

    def test_missing_email_arg_raises_error(self):
        """Command should require --email argument."""
        with pytest.raises(CommandError, match="--email"):
            call_command(
                "create_superuser_if_missing",
                "--password",
                "adminpass123",
            )

    def test_missing_password_arg_raises_error(self):
        """Command should require --password argument."""
        with pytest.raises(CommandError, match="--password"):
            call_command(
                "create_superuser_if_missing",
                "--email",
                "admin@test.com",
            )


@pytest.mark.django_db
class TestSeedData:
    """Tests for seed_data management command."""

    def test_command_runs_without_errors(self):
        """Seed data command should populate database."""
        out = StringIO()
        call_command("seed_data", stdout=out)
        output = out.getvalue()
        assert "Seeded" in output or "Created" in output or "Done" in output

    def test_creates_sample_tasks(self):
        """Seed data should create tasks."""
        call_command("seed_data", stdout=StringIO())
        from apps.tasks.models import Task

        assert Task.objects.exists()


@pytest.mark.django_db
class TestWarmCache:
    """Tests for warm_cache management command."""

    def test_command_runs_without_errors(self):
        """Warm cache command should populate Redis cache."""
        out = StringIO()
        call_command("warm_cache", stdout=out)
        output = out.getvalue()
        assert "Warmed" in output or "Cached" in output or "Done" in output

    def test_handles_empty_database(self):
        """Warm cache should not crash with empty DB."""
        out = StringIO()
        call_command("warm_cache", stdout=out)
        assert out.getvalue() is not None
