"""Serializers for the Task API.

Provides a TranslatableModelSerializer that handles multilingual
content via django-parler-rest, with explicit create/update logic
for translation management.
"""

from django.conf import settings
from parler_rest.serializers import TranslatableModelSerializer, TranslatedFieldsField
from rest_framework import serializers

from apps.tasks.models import Task


class TaskSerializer(TranslatableModelSerializer):
    """Serializer for multilingual Task instances.

    Handles translation fields (title, description) via
    ``TranslatedFieldsField``, exposes a read-only ``status_display``
    label, and injects the resolved request language into the
    serialized output.

    Attributes:
        translations: Nested translation objects keyed by language code.
        language: The language resolved for the current request.
        status_display: Human-readable status label.
    """

    translations = TranslatedFieldsField(shared_model=Task)
    language = serializers.SerializerMethodField()
    status_display = serializers.CharField(
        source="get_status_display",
        read_only=True,
    )

    class Meta:
        """Metadata for TaskSerializer."""

        model = Task
        fields = [
            "id",
            "translations",
            "language",
            "status",
            "status_display",
            "is_active",
            "created_at",
            "updated_at",
            "user",
        ]

    def get_language(self, obj: Task) -> str:
        """Return the resolved language for the current request.

        Falls back to ``'en'`` if the request object does not carry
        a ``language`` attribute (e.g. during testing).

        Args:
            obj: The Task instance being serialized.

        Returns:
            The ISO language code string.
        """
        request = self.context.get("request")
        if request and hasattr(request, "language"):
            return request.language
        return "en"

    def create(self, validated_data: dict) -> Task:
        """Create a new Task with translations.

        Pops translation data from ``validated_data``, creates the
        base Task record, then applies the title and description
        for the current request language.

        Args:
            validated_data: Cleaned data from the serializer.

        Returns:
            The newly created Task instance.
        """
        translations_data = validated_data.pop("translations", {})
        current_lang = self.get_language(None)

        task = Task.objects.create(**validated_data)

        if translations_data:
            task.set_current_language(current_lang)
            task.title = translations_data.get(current_lang, {}).get(
                "title", ""
            )
            task.description = translations_data.get(current_lang, {}).get(
                "description", ""
            )
            task.save()

        return task

    def update(self, instance: Task, validated_data: dict) -> Task:
        """Update an existing Task and its translations.

        Applies non-translation fields directly, then updates the
        translation for the current request language if present in
        the payload.

        Args:
            instance: The Task instance to update.
            validated_data: Cleaned data from the serializer.

        Returns:
            The updated Task instance.
        """
        translations_data = validated_data.pop("translations", {})
        current_lang = self.get_language(None)

        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        if translations_data and current_lang in translations_data:
            instance.set_current_language(current_lang)
            instance.title = translations_data[current_lang].get(
                "title", instance.title
            )
            instance.description = translations_data[current_lang].get(
                "description", instance.description
            )

        instance.save()
        return instance