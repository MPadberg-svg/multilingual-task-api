"""Pydantic v2 structured output schemas for AI Assist endpoints."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, model_validator


class LocalizedTaskContent(BaseModel):
    """Translated title and description for a single language."""

    title: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=10000)

    @model_validator(mode="before")
    @classmethod
    def _coerce_shorthand_string(cls, data: Any) -> Any:
        if isinstance(data, str):
            return {"title": data[:255], "description": ""}
        return data


class TranslationSuggestionSchema(BaseModel):
    """Structured EN/ES/FR translation response."""

    en: LocalizedTaskContent
    es: LocalizedTaskContent
    fr: LocalizedTaskContent


class PromptQualitySchema(BaseModel):
    """Structured prompt quality evaluation response."""

    score: int = Field(ge=0, le=100)
    improvements: list[str] = Field(default_factory=list)
    analysis: str = Field(default="")

    @model_validator(mode="before")
    @classmethod
    def _normalize_feedback_alias(cls, data: Any) -> Any:
        if isinstance(data, dict):
            normalized = dict(data)
            if "analysis" not in normalized and "feedback" in normalized:
                normalized["analysis"] = str(normalized.pop("feedback"))
            return normalized
        return data


class RLHFMetadataSchema(BaseModel):
    """Metadata block for RLHF pytest generation."""

    language: str = "python"
    framework: str = "pytest"
    edge_cases: list[str] = Field(default_factory=list)


class RLHFTestCaseSchema(BaseModel):
    """Structured RLHF test-case response."""

    instruction: str
    input: str
    output: str
    metadata: RLHFMetadataSchema = Field(default_factory=RLHFMetadataSchema)

    @model_validator(mode="before")
    @classmethod
    def _coerce_list_response(cls, data: Any) -> Any:
        if isinstance(data, list) and data:
            first = data[0] if isinstance(data[0], dict) else {"case": str(data[0])}
            return {
                "instruction": str(first.get("instruction", "Generated test cases")),
                "input": str(first.get("input", "")),
                "output": str(first.get("output", first.get("expected", ""))),
                "metadata": {
                    "language": "python",
                    "framework": "pytest",
                    "edge_cases": [str(item) for item in data[:10]],
                },
            }
        return data
