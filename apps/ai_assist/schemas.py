"""Pydantic v2 structured output schemas for AI Assist endpoints."""

from __future__ import annotations

from typing import Any, Literal

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


class RLHFJudgeProbabilitiesSchema(BaseModel):
    """Probability distribution returned by the active-learning RLHF pairwise LLM judge."""

    response_a: float = Field(default=0.34, ge=0.0, le=1.0)
    response_b: float = Field(default=0.33, ge=0.0, le=1.0)
    tie: float = Field(default=0.33, ge=0.0, le=1.0)


class RLHFJudgeEvaluationSchema(BaseModel):
    """Structured pairwise preference & calibrated probability distribution from LLM judge."""

    preference: Literal["response_a", "response_b", "tie"]
    choice_probabilities: RLHFJudgeProbabilitiesSchema = Field(
        default_factory=RLHFJudgeProbabilitiesSchema
    )
    rationale: str = Field(default="", max_length=4000)

    @model_validator(mode="before")
    @classmethod
    def _normalize_aliases(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        normalized = dict(data)
        raw_pref = str(normalized.get("preference") or "tie").strip().lower()
        alias_map = {
            "a": "response_a",
            "b": "response_b",
            "response_a": "response_a",
            "response_b": "response_b",
            "tie": "tie",
        }
        if raw_pref in alias_map:
            normalized["preference"] = alias_map[raw_pref]
        if "choice_probabilities" not in normalized and isinstance(
            normalized.get("probabilities"), dict
        ):
            normalized["choice_probabilities"] = normalized.pop("probabilities")
        return normalized
