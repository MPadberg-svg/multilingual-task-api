"""Serializers for the Task API and RLHF annotation workflow.

Provides a multilingual ``TaskSerializer`` that supports writable
``translations`` (and optional top-level ``title`` / ``description`` in the
active request language) while validating and sanitizing all inputs, plus
structured RLHF annotation, task-claim, and adjudication serializers.
"""

from __future__ import annotations

from typing import Any

from django.conf import settings
from django.db import transaction

from rest_framework import serializers
from rest_framework.exceptions import PermissionDenied

from apps.core.security import InputValidator
from apps.tasks.models import Task, TaskAnnotation


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
    """Serializer for multilingual Task instances and RLHF leasing/consensus state."""

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
    auto_translate = serializers.BooleanField(write_only=True, required=False, default=False)
    language = serializers.SerializerMethodField()
    status_display = serializers.CharField(
        source="get_status_display",
        read_only=True,
    )
    annotation_count = serializers.SerializerMethodField()
    gold_choice = serializers.CharField(required=False, allow_blank=True, default="")

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
            "priority",
            "required_annotations",
            "claimed_by",
            "claimed_until",
            "consensus_score",
            "consensus_choice",
            "is_gold",
            "gold_choice",
            "annotation_count",
            "auto_translate",
            "is_active",
            "organization",
            "created_at",
            "updated_at",
            "user",
        ]
        read_only_fields = [
            "id",
            "user",
            "organization",
            "claimed_by",
            "claimed_until",
            "consensus_score",
            "consensus_choice",
            "annotation_count",
            "created_at",
            "updated_at",
        ]

    def _active_language(self) -> str:
        request = self.context.get("request")
        lang = getattr(request, "language", "en") if request is not None else "en"
        return str(lang or "en").lower()

    def _can_view_gold(self, instance: Task | None = None) -> bool:
        """Return True iff the caller may inspect or author hidden gold calibration metadata."""
        request = self.context.get("request")
        if instance is not None and instance.organization_id is None:
            return request is not None
        if request is None:
            return False
        if instance is None and getattr(request, "organization", None) is None:
            return True
        if bool(getattr(request.user, "is_superuser", False)):
            return True
        return getattr(request, "membership_role", None) in ("admin", "owner")

    def get_language(self, obj: Task) -> str:
        """Return the resolved language for the current request."""
        return self._active_language()

    def get_annotation_count(self, obj: Task) -> int:
        annotated = getattr(obj, "annotation_count_val", None)
        if isinstance(annotated, int):
            return annotated
        prefetched = getattr(obj, "_prefetched_objects_cache", {})
        if "annotations" in prefetched:
            return len(prefetched["annotations"])
        return int(obj.annotations.count())

    @staticmethod
    def _clean_text(value: str, field_label: str, max_length: int) -> str:
        is_dangerous, reason = InputValidator.detect_injection(value)
        if is_dangerous:
            raise serializers.ValidationError(f"Invalid {field_label}: {reason}")
        try:
            return InputValidator.sanitize_string(value, max_length=max_length)
        except ValueError as exc:
            raise serializers.ValidationError(str(exc)) from exc

    def validate_required_annotations(self, value: int) -> int:
        if value < 1 or value > 25:
            raise serializers.ValidationError("required_annotations must be between 1 and 25.")
        return value

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

        gold_fields_supplied = "is_gold" in attrs or (
            "gold_choice" in self.initial_data
            if isinstance(getattr(self, "initial_data", None), dict)
            else False
        )
        if gold_fields_supplied and not self._can_view_gold(self.instance):
            raise PermissionDenied(
                "Only organization admins or owners can configure gold calibration tasks."
            )

        alias_map = {
            "": "",
            "a": "response_a",
            "b": "response_b",
            "response_a": "response_a",
            "response_b": "response_b",
            "tie": "tie",
        }
        raw_gold_choice = attrs.get(
            "gold_choice",
            getattr(self.instance, "gold_choice", "") if self.instance is not None else "",
        )
        norm_gold = str(raw_gold_choice or "").strip().lower()
        if norm_gold not in alias_map:
            raise serializers.ValidationError(
                {"gold_choice": "Must be one of 'response_a', 'response_b', or 'tie'."}
            )
        resolved_gold_choice = alias_map[norm_gold]
        resolved_is_gold = bool(
            attrs.get(
                "is_gold",
                getattr(self.instance, "is_gold", False) if self.instance is not None else False,
            )
        )

        if resolved_is_gold and not resolved_gold_choice:
            raise serializers.ValidationError(
                {
                    "gold_choice": (
                        "Gold calibration tasks require a gold_choice ('response_a', "
                        "'response_b', or 'tie')."
                    )
                }
            )
        if not resolved_is_gold and resolved_gold_choice:
            raise serializers.ValidationError(
                {"is_gold": "Set is_gold=true when specifying gold_choice."}
            )
        if "gold_choice" in attrs or resolved_is_gold:
            attrs["gold_choice"] = resolved_gold_choice

        return attrs

    def to_representation(self, instance: Task) -> dict[str, Any]:
        """Serialize Task with resolved language fields, translations, and RLHF metadata."""
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
        dt_field = serializers.DateTimeField()

        rep: dict[str, Any] = {
            "id": str(instance.id),
            "title": resolved_title,
            "description": resolved_description,
            "translations": translations_out,
            "language": lang,
            "status": instance.status,
            "status_display": instance.get_status_display(),
            "priority": instance.priority,
            "required_annotations": instance.required_annotations,
            "claimed_by": str(instance.claimed_by_id) if instance.claimed_by_id else None,
            "claimed_until": (
                dt_field.to_representation(instance.claimed_until)
                if instance.claimed_until
                else None
            ),
            "consensus_score": instance.consensus_score,
            "consensus_choice": instance.consensus_choice,
            "annotation_count": self.get_annotation_count(instance),
            "is_active": instance.is_active,
            "organization": str(instance.organization_id) if instance.organization_id else None,
            "created_at": dt_field.to_representation(instance.created_at),
            "updated_at": dt_field.to_representation(instance.updated_at),
            "user": instance.user_id,
        }
        if self._can_view_gold(instance):
            rep["is_gold"] = instance.is_gold
            rep["gold_choice"] = instance.gold_choice
        return rep

    @transaction.atomic
    def create(self, validated_data: dict[str, Any]) -> Task:
        """Create a new Task and persist all provided translations atomically."""
        auto_translate = bool(validated_data.pop("auto_translate", False))
        translations_data: dict[str, dict[str, str]] = validated_data.pop("translations", {})
        task = Task.objects.create(**validated_data)

        for lang_code, trans_data in translations_data.items():
            task.set_current_language(lang_code)
            task.title = trans_data.get("title", "")
            task.description = trans_data.get("description", "")
            task.save()

        setattr(task, "_auto_translate_requested", auto_translate)
        return task

    @transaction.atomic
    def update(self, instance: Task, validated_data: dict[str, Any]) -> Task:
        """Update an existing Task and any provided language translations atomically."""
        validated_data.pop("auto_translate", None)
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


class TaskAnnotationSerializer(serializers.ModelSerializer):
    """Serializer for structured RLHF preference and rubric annotations."""

    annotator_email = serializers.EmailField(source="annotator.email", read_only=True)
    preference = serializers.CharField(required=False)
    preference_choice = serializers.CharField(write_only=True, required=False)
    overall_score = serializers.IntegerField(
        write_only=True, required=False, min_value=1, max_value=5
    )
    helpfulness_score = serializers.IntegerField(
        write_only=True, required=False, min_value=1, max_value=5
    )
    harmlessness_score = serializers.IntegerField(
        write_only=True, required=False, min_value=1, max_value=5
    )
    honesty_score = serializers.IntegerField(
        write_only=True, required=False, min_value=1, max_value=5
    )
    duration_ms = serializers.IntegerField(write_only=True, required=False, min_value=0)
    language = serializers.CharField(write_only=True, required=False, max_length=10)

    class Meta:
        model = TaskAnnotation
        fields = [
            "id",
            "task",
            "annotator",
            "annotator_email",
            "preference",
            "preference_choice",
            "rubric_scores",
            "overall_score",
            "helpfulness_score",
            "harmlessness_score",
            "honesty_score",
            "rationale",
            "response_a",
            "response_b",
            "duration_seconds",
            "duration_ms",
            "language",
            "created_at",
        ]
        read_only_fields = ["id", "task", "annotator", "annotator_email", "created_at"]

    def _clean_text(self, value: str, field_name: str, max_length: int) -> str:
        if not value:
            return ""
        is_bad, reason = InputValidator.detect_injection(value)
        if is_bad:
            raise serializers.ValidationError(f"Invalid {field_name}: {reason}")
        try:
            return InputValidator.sanitize_string(value, max_length=max_length)
        except ValueError as exc:
            raise serializers.ValidationError(str(exc)) from exc

    def validate_rationale(self, value: str) -> str:
        return self._clean_text(value, "rationale", max_length=5000)

    def validate_response_a(self, value: str) -> str:
        return self._clean_text(value, "response_a", max_length=10000)

    def validate_response_b(self, value: str) -> str:
        return self._clean_text(value, "response_b", max_length=10000)

    def validate_rubric_scores(self, value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise serializers.ValidationError("rubric_scores must be a JSON object.")
        for k, v in value.items():
            if k == "language":
                continue
            if not isinstance(v, int) or v < 1 or v > 5:
                raise serializers.ValidationError(
                    f"Rubric score '{k}' must be an integer between 1 and 5."
                )
        return dict(value)

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        alias_map = {
            "a": "response_a",
            "b": "response_b",
            "response_a": "response_a",
            "response_b": "response_b",
            "tie": "tie",
        }
        raw_pref = attrs.pop("preference_choice", None) or attrs.get("preference")
        if not raw_pref or str(raw_pref).lower() not in alias_map:
            raise serializers.ValidationError(
                {"preference": "Must be one of 'response_a', 'response_b', or 'tie'."}
            )
        attrs["preference"] = alias_map[str(raw_pref).lower()]

        scores = dict(attrs.get("rubric_scores") or {})
        for field_key, score_key in (
            ("overall_score", "overall"),
            ("helpfulness_score", "helpfulness"),
            ("harmlessness_score", "harmlessness"),
            ("honesty_score", "honesty"),
        ):
            val = attrs.pop(field_key, None)
            if val is not None:
                scores[score_key] = int(val)

        lang = attrs.pop("language", None)
        if lang:
            scores["language"] = str(lang)[:10]
        attrs["rubric_scores"] = scores

        dur_ms = attrs.pop("duration_ms", None)
        if dur_ms is not None and "duration_seconds" not in attrs:
            attrs["duration_seconds"] = max(0, int(dur_ms) // 1000)

        return attrs


class TaskAdjudicateSerializer(serializers.Serializer):
    """Payload for ``POST /api/v1/tasks/{id}/adjudicate/``."""

    consensus_choice = serializers.ChoiceField(
        choices=["response_a", "response_b", "tie", "a", "b"]
    )
    rationale = serializers.CharField(max_length=2000, required=False, allow_blank=True, default="")

    def validate_consensus_choice(self, value: str) -> str:
        return {"a": "response_a", "b": "response_b"}.get(value, value)

    def validate_rationale(self, value: str) -> str:
        if not value:
            return ""
        is_bad, reason = InputValidator.detect_injection(value)
        if is_bad:
            raise serializers.ValidationError(f"Invalid rationale: {reason}")
        return InputValidator.sanitize_string(value, max_length=2000)


class TaskClaimRequestSerializer(serializers.Serializer):
    """Optional lease configuration for ``POST /api/v1/tasks/claim/``."""

    lease_seconds = serializers.IntegerField(
        required=False, default=900, min_value=60, max_value=7200
    )
    priority = serializers.ChoiceField(
        choices=["low", "medium", "high", "critical"],
        required=False,
        allow_null=True,
        default=None,
    )
