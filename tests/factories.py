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
    """Generate Django user instances with hashed passwords."""

    class Meta:
        model = User

    username = factory.Sequence(lambda n: f"user{n}")
    email = factory.LazyAttribute(lambda obj: f"{obj.username}@example.com")
    password = factory.PostGenerationMethodCall("set_password", "testpass123")


class TaskFactory(factory.django.DjangoModelFactory):
    """Generate Task instances with EN/ES/FR translations pre-populated.

    The ``translations`` post-generation hook sets up django-parler
    translations for all three supported languages using locale-aware
    Faker data.
    """

    class Meta:
        model = Task

    status = factory.Iterator(["draft", "pending", "completed", "archived"])
    user = factory.SubFactory(UserFactory)

    @factory.post_generation
    def translations(self, create, extracted, **kwargs):
        """Populate EN/ES/FR translations after the Task is created.

        Args:
            create: Whether the instance was created (vs. built).
            extracted: Any explicitly passed translation data.
            **kwargs: Additional keyword arguments.
        """
        if not create:
            return

        # English
        self.set_current_language("en")
        self.title = faker_en.sentence(nb_words=4)
        self.description = faker_en.paragraph()
        self.save()

        # Spanish
        self.set_current_language("es")
        self.title = faker_es.sentence(nb_words=4)
        self.description = faker_es.paragraph()
        self.save()

        # French
        self.set_current_language("fr")
        self.title = faker_fr.sentence(nb_words=4)
        self.description = faker_fr.paragraph()
        self.save()