"""Serializers for the Task API.

Provides a TranslatableModelSerializer that handles multilingual
content manually without django-parler-rest, which is incompatible
with Django 5.1 (removed ugettext_lazy).
"""

from django.conf import settings
from rest_framework import serializers

from apps.tasks.models import Task


class TaskSerializer(serializers.ModelSerializer):
    """Serializer for multilingual Task instances.

    Handles translation fields (title, description) manually,
    exposes a read-only ``status_display`` label, and injects
    the resolved request language into the serialized output.
    """

    translations = serializers.SerializerMethodField()
    language = serializers.SerializerMethodField()
    status_display = serializers.CharField(
        source="get_status_display",
        read_only=True,
    )

    class Meta:
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
        """Return the resolved language for the current request."""
        request = self.context.get("request")
        if request and hasattr(request, "language"):
            return request.language
        return "en"

    def get_translations(self, obj: Task) -> dict:
        """Return all available translations as a nested dict."""
        result = {}
        for translation in obj.translations.all():
            result[translation.language_code] = {
                "title": translation.title,
                "description": translation.description,
            }
        return result

    def create(self, validated_data: dict) -> Task:
        """Create a new Task with translations."""
        translations_data = validated_data.pop("translations", {})
        current_lang = self.get_language(None)

        task = Task.objects.create(**validated_data)

        if translations_data and current_lang in translations_data:
            task.set_current_language(current_lang)
            task.title = translations_data[current_lang].get("title", "")
            task.description = translations_data[current_lang].get("description", "")
            task.save()

        return task

    def update(self, instance: Task, validated_data: dict) -> Task:
        """Update an existing Task and its translations."""
        translations_data = validated_data.pop("translations", {})
        current_lang = self.get_language(None)

        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        if translations_data and current_lang in translations_data:
            instance.set_current_language(current_lang)
            instance.title = translations_data[current_lang].get(
                "title", instance.safe_translation_getter("title", any_language=True) or ""
            )
            instance.description = translations_data[current_lang].get(
                "description", instance.safe_translation_getter("description", any_language=True) or ""
            )

        instance.save()
        return instance
