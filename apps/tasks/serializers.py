"""Serializers for the Task API.

Provides a multilingual ``TaskSerializer`` that supports writable
``translations`` (and optional top-level ``title`` / ``description`` in the
active request language) while validating and sanitizing all inputs.
"""

from __future__ import annotations

from typing import Any

from django.conf import settings
from django.db import transaction

from rest_framework import serializers

from apps.core.security import InputValidator
from apps.tasks.models import Task


def _supported_languages() -> set[str]:
    return {str(code).lower() for code, _ in getattr(settings, "LANGUAGES", [("en", "English")])}


class TaskTranslationPayloadSerializer(serializers.Serializer):
    """Validates a single language's ``title`` and ``description`` payload."""

    title = serializers.CharField(
        max_length=255,
        required=False,
        allow_blank=True,
    )
    description = serializers.CharField(
        max_length=10000,
        required=False,
        allow_blank=True,
        default="",
    )


class TaskSerializer(serializers.ModelSerializer):
    """Serializer for multilingual Task instances.

    Supports writing translations either via a nested ``translations`` mapping
    (``{"en": {"title": "...", "description": "..."}, "es": {...}}``) or via
    convenience top-level ``title`` / ``description`` fields scoped to the
    resolved request language.
    """

    translations = serializers.DictField(
        child=TaskTranslationPayloadSerializer(),
        required=False,
    )
    title = serializers.CharField(
        max_length=255,
        required=False,
        allow_blank=False,
    )
    description = serializers.CharField(
        max_length=10000,
        required=False,
        allow_blank=True,
    )
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
            "organization",
            "created_at",
            "updated_at",
            "user",
        ]
        read_only_fields = ["id", "user", "organization", "created_at", "updated_at"]

    def _active_language(self) -> str:
        request = self.context.get("request")
        lang = getattr(request, "language", "en") if request is not None else "en"
        return str(lang or "en").lower()

    def get_language(self, obj: Task) -> str:
        """Return the resolved language for the current request."""
        return self._active_language()

    @staticmethod
    def _clean_text(value: str, field_label: str, max_length: int) -> str:
        is_dangerous, reason = InputValidator.detect_injection(value)
        if is_dangerous:
            raise serializers.ValidationError(f"Invalid {field_label}: {reason}")
        try:
            return InputValidator.sanitize_string(value, max_length=max_length)
        except ValueError as exc:
            raise serializers.ValidationError(str(exc)) from exc

    def validate_translations(self, value: dict[str, dict[str, Any]]) -> dict[str, dict[str, str]]:
        """Validate language codes and sanitize translated title/description text."""
        if not isinstance(value, dict):
            raise serializers.ValidationError("Translations must be a JSON object.")

        supported = _supported_languages()
        cleaned_map: dict[str, dict[str, str]] = {}

        for raw_lang, payload in value.items():
            lang_code = str(raw_lang).strip().lower()
            if lang_code not in supported:
                raise serializers.ValidationError(
                    f"Unsupported language code '{raw_lang}'. Supported: {sorted(supported)}."
                )
            if not isinstance(payload, dict):
                raise serializers.ValidationError(
                    f"Translation entry for '{lang_code}' must be an object."
                )

            entry: dict[str, str] = {}
            if "title" in payload:
                cleaned_title = self._clean_text(
                    str(payload["title"]), f"{lang_code}.title", max_length=255
                )
                if not cleaned_title:
                    raise serializers.ValidationError(
                        f"Translation title for '{lang_code}' cannot be empty."
                    )
                entry["title"] = cleaned_title
            if "description" in payload:
                entry["description"] = self._clean_text(
                    str(payload["description"]),
                    f"{lang_code}.description",
                    max_length=10000,
                )
            cleaned_map[lang_code] = entry

        return cleaned_map

    def validate_title(self, value: str) -> str:
        cleaned = self._clean_text(value, "title", max_length=255)
        if not cleaned:
            raise serializers.ValidationError("Title cannot be empty.")
        return cleaned

    def validate_description(self, value: str) -> str:
        return self._clean_text(value, "description", max_length=10000)

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        """Merge convenience top-level title/description into translations map."""
        translations_data: dict[str, dict[str, str]] = dict(attrs.get("translations") or {})
        active_lang = self._active_language()
        if active_lang not in _supported_languages():
            active_lang = "en"

        top_title = attrs.pop("title", None)
        top_description = attrs.pop("description", None)
        if top_title is not None or top_description is not None:
            merged_entry = dict(translations_data.get(active_lang, {}))
            if top_title is not None and "title" not in merged_entry:
                merged_entry["title"] = top_title
            if top_description is not None and "description" not in merged_entry:
                merged_entry["description"] = top_description
            translations_data[active_lang] = merged_entry

        if self.instance is None:
            # Creating a new task requires at least one non-empty title
            has_any_title = any(
                bool(entry.get("title", "").strip()) for entry in translations_data.values()
            )
            if not has_any_title:
                raise serializers.ValidationError(
                    {
                        "translations": (
                            "At least one language translation with a non-empty title is required."
                        )
                    }
                )
        else:
            # For new language rows added during update, ensure title is present if row didn't exist
            existing_langs = {t.language_code for t in self.instance.translations.all()}
            for lang_code, entry in translations_data.items():
                if lang_code not in existing_langs and not entry.get("title", "").strip():
                    raise serializers.ValidationError(
                        {
                            "translations": (
                                f"New translation '{lang_code}' must include a non-empty title."
                            )
                        }
                    )

        attrs["translations"] = translations_data
        return attrs

    def to_representation(self, instance: Task) -> dict[str, Any]:
        """Serialize Task with resolved language fields and full translations dictionary."""
        lang = self._active_language()
        translations_out: dict[str, dict[str, str]] = {}
        for trans in instance.translations.all():
            translations_out[trans.language_code] = {
                "title": trans.title,
                "description": trans.description,
            }

        resolved_title = (
            instance.safe_translation_getter("title", language_code=lang, any_language=True) or ""
        )
        resolved_description = (
            instance.safe_translation_getter("description", language_code=lang, any_language=True)
            or ""
        )

        return {
            "id": str(instance.id),
            "title": resolved_title,
            "description": resolved_description,
            "translations": translations_out,
            "language": lang,
            "status": instance.status,
            "status_display": instance.get_status_display(),
            "is_active": instance.is_active,
            "organization": str(instance.organization_id) if instance.organization_id else None,
            "created_at": serializers.DateTimeField().to_representation(instance.created_at),
            "updated_at": serializers.DateTimeField().to_representation(instance.updated_at),
            "user": instance.user_id,
        }

    @transaction.atomic
    def create(self, validated_data: dict[str, Any]) -> Task:
        """Create a new Task and persist all provided translations atomically."""
        translations_data: dict[str, dict[str, str]] = validated_data.pop("translations", {})
        task = Task.objects.create(**validated_data)

        for lang_code, trans_data in translations_data.items():
            task.set_current_language(lang_code)
            task.title = trans_data.get("title", "")
            task.description = trans_data.get("description", "")
            task.save()

        return task

    @transaction.atomic
    def update(self, instance: Task, validated_data: dict[str, Any]) -> Task:
        """Update an existing Task and any provided language translations atomically."""
        translations_data: dict[str, dict[str, str]] = validated_data.pop("translations", {})

        model_fields_changed = False
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
            model_fields_changed = True

        if model_fields_changed and not translations_data:
            instance.save()

        for lang_code, trans_data in translations_data.items():
            existing_title = (
                instance.safe_translation_getter(
                    "title", language_code=lang_code, any_language=False
                )
                or ""
            )
            existing_description = (
                instance.safe_translation_getter(
                    "description", language_code=lang_code, any_language=False
                )
                or ""
            )
            instance.set_current_language(lang_code)
            instance.title = trans_data.get("title", existing_title)
            instance.description = trans_data.get("description", existing_description)
            instance.save()

        return instance
