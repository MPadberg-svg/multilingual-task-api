"""Test factories for rapid data generation.

Provides ``UserFactory`` and ``TaskFactory`` using factory_boy and
locale-specific Faker instances for EN/ES/FR content.

Example:
    >>> user = UserFactory()
    >>> task = TaskFactory(user=user)
    >>> task.title  # English by default
    'Review the quarterly annotation metrics.'
"""

import factory
from django.contrib.auth import get_user_model
from faker import Faker

from apps.tasks.models import Task

User = get_user_model()

# Locale-specific Faker instances for multilingual content.
faker_en = Faker("en_US")
faker_es = Faker("es_ES")
faker_fr = Faker("fr_FR")


class UserFactory(factory.django.DjangoModelFactory):
    """Generate CustomUser instances with email authentication and hashed passwords."""

    class Meta:
        model = User
        django_get_or_create = ("email",)

    email = factory.Sequence(lambda n: f"user{n}@example.com")
    first_name = factory.Faker("first_name")
    last_name = factory.Faker("last_name")
    is_active = True
    is_staff = False
    password = factory.PostGenerationMethodCall("set_password", "testpass123")


class TaskFactory(factory.django.DjangoModelFactory):
    """Generate Task instances with EN/ES/FR translations pre-populated."""

    class Meta:
        model = Task

    # FIXED: "draft" is NOT a valid status choice — replaced with "in_progress"
    status = factory.Iterator(["pending", "in_progress", "completed", "archived"])
    user = factory.SubFactory(UserFactory)

    @factory.post_generation
    def translations(self, create, extracted, **kwargs):
        """Populate EN/ES/FR translations after the Task is created."""
        if not create:
            return

        self.set_current_language("en")
        self.title = faker_en.sentence(nb_words=4)
        self.description = faker_en.paragraph()
        self.save()

        self.set_current_language("es")
        self.title = faker_es.sentence(nb_words=4)
        self.description = faker_es.paragraph()
        self.save()

        self.set_current_language("fr")
        self.title = faker_fr.sentence(nb_words=4)
        self.description = faker_fr.paragraph()
        self.save()