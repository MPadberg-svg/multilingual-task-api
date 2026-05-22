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
    title = serializers.SerializerMethodField()
    description = serializers.SerializerMethodField()
    language = serializers.SerializerMethodField()
    status_display = serializers.CharField(
        source="get_status_display",
        read_only=True,
    )

    class Meta:
        model = Task
        fields = [
            "id",
            "title",
            "description",
            "translations",
            "language",
            "status",
            "status_display",
            "is_active",
            "created_at",
            "updated_at",
            "user",
        ]
        read_only_fields = ["user"]

    def get_language(self, obj: Task) -> str:
        """Return the resolved language for the current request."""
        request = self.context.get("request")
        if request and hasattr(request, "language"):
            return request.language
        return "en"

    def get_title(self, obj: Task) -> str:
        """Return title in the resolved request language."""
        request = self.context.get("request")
        lang = getattr(request, "language", "en") if request else "en"
        return obj.safe_translation_getter("title", language_code=lang, any_language=True) or ""

    def get_description(self, obj: Task) -> str:
        """Return description in the resolved request language."""
        request = self.context.get("request")
        lang = getattr(request, "language", "en") if request else "en"
        return obj.safe_translation_getter("description", language_code=lang, any_language=True) or ""

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
        """Create a new Task with all translations."""
        translations_data = validated_data.pop("translations", {})

        task = Task.objects.create(**validated_data)

        # Save ALL translations, not just current language
        for lang_code, trans_data in translations_data.items():
            task.set_current_language(lang_code)
            task.title = trans_data.get("title", "")
            task.description = trans_data.get("description", "")
            task.save()

        return task

    def update(self, instance: Task, validated_data: dict) -> Task:
        """Update an existing Task and its translations."""
        translations_data = validated_data.pop("translations", {})

        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        # Update ALL provided translations
        for lang_code, trans_data in translations_data.items():
            instance.set_current_language(lang_code)
            instance.title = trans_data.get(
                "title", instance.safe_translation_getter("title", any_language=True) or ""
            )
            instance.description = trans_data.get(
                "description", instance.safe_translation_getter("description", any_language=True) or ""
            )

        instance.save()
        return instance