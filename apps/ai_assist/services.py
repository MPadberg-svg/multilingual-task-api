"""AI Assist service layer with structured outputs, caching, and circuit breaker resilience.

Provides ``AIService`` for LLM-backed task operations including translation
suggestions, prompt quality evaluation, and RLHF test-case generation.
All public methods validate and sanitize user input before processing,
enforce Pydantic v2 output schemas, and avoid caching degraded/error responses.

Cache keys follow the project convention:
    ``mltask:ai:{user_id}:{lang}:{sha256_hash}``
"""

from __future__ import annotations

import contextvars
import hashlib
import json
import logging
import re
from typing import Any

from django.conf import settings
from django.core.cache import cache

from pydantic import ValidationError as PydanticValidationError

from apps.ai_assist.circuit_breaker import CircuitOpenError, openai_circuit_breaker
from apps.ai_assist.prompt_templates import SYSTEM_GUARDRAIL_PROMPT, PromptTemplateManager
from apps.ai_assist.schemas import (
    PromptQualitySchema,
    RLHFTestCaseSchema,
    TranslationSuggestionSchema,
)
from apps.core.finops import AIBudgetExceededError, enforce_org_ai_budget
from apps.core.security import InputValidator
from apps.core.tracing import start_span
from apps.core.views import record_ai_token_usage, record_cache_hit, record_cache_miss

logger = logging.getLogger(__name__)

_ACTIVE_ORG_ID: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "_ACTIVE_ORG_ID", default=None
)
_ACTIVE_USER_ID: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "_ACTIVE_USER_ID", default=None
)
_ACTIVE_OPERATION: contextvars.ContextVar[str] = contextvars.ContextVar(
    "_ACTIVE_OPERATION", default="chat.completions"
)

CACHE_TTL_AI: int = settings.CACHE_TTL.get("ai_suggestions", 3600)
OPENAI_TIMEOUT_SECONDS: float = 30.0


class UpstreamAIResponseError(RuntimeError):
    """Raised when the upstream AI provider returns empty or invalid structured JSON."""


def _make_cache_key(user_id: str, lang: str, params: dict[str, Any]) -> str:
    """Generate a deterministic SHA256 cache key."""
    payload = json.dumps(params, sort_keys=True, ensure_ascii=True)
    digest = hashlib.sha256(payload.encode()).hexdigest()[:16]
    return f"mltask:ai:{user_id}:{lang}:{digest}"


def _safe_json_parse(raw: str) -> Any:
    """Fail-safe JSON parser supporting fenced blocks and trailing commas."""
    if not raw or not isinstance(raw, str):
        return {}

    cleaned = raw.strip()
    if cleaned.startswith("```json"):
        cleaned = cleaned[7:]
    elif cleaned.startswith("```"):
        cleaned = cleaned[3:]
    if cleaned.endswith("```"):
        cleaned = cleaned[:-3]
    cleaned = cleaned.strip()

    cleaned = re.sub(r",\s*([\}\]])", r"\1", cleaned)

    try:
        return json.loads(cleaned)
    except (json.JSONDecodeError, TypeError) as exc:
        logger.warning("JSON parse failed: %s", exc)
        return {}


class AIService:
    """Orchestrates LLM calls with caching, Pydantic validation, and resilience."""

    def __init__(self) -> None:
        self._client: Any = None
        self.template_manager = PromptTemplateManager()

    @property
    def client(self) -> Any:
        """Lazy OpenAI client initialisation with explicit timeout and bounded retries."""
        if self._client is None:
            import openai

            self._client = openai.OpenAI(
                api_key=settings.OPENAI_API_KEY,
                timeout=OPENAI_TIMEOUT_SECONDS,
                max_retries=1,
            )
        return self._client

    def _call_llm(
        self,
        prompt: str,
        temperature: float = 0.3,
        system_prompt: str = SYSTEM_GUARDRAIL_PROMPT,
    ) -> str:
        """Call OpenAI through the circuit breaker with system/user role separation.

        Propagates ``CircuitOpenError`` when the circuit breaker is open so
        callers never cache degraded fallback payloads as valid responses.
        """

        def _raw_call() -> str:
            with start_span(
                "openai.chat.completions",
                kind="CLIENT",
                attributes={
                    "gen_ai.system": "openai",
                    "gen_ai.request.model": str(settings.OPENAI_MODEL),
                    "organization.id": _ACTIVE_ORG_ID.get(),
                },
            ) as span:
                response = self.client.chat.completions.create(
                    model=settings.OPENAI_MODEL,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt},
                    ],
                    temperature=temperature,
                    max_tokens=settings.OPENAI_MAX_TOKENS,
                    response_format={"type": "json_object"},
                )
                usage = getattr(response, "usage", None)
                raw_pt = getattr(usage, "prompt_tokens", 0)
                raw_ct = getattr(usage, "completion_tokens", 0)
                prompt_tokens = int(raw_pt) if isinstance(raw_pt, (int, float)) else 0
                completion_tokens = int(raw_ct) if isinstance(raw_ct, (int, float)) else 0
                span.set_attribute("gen_ai.usage.input_tokens", prompt_tokens)
                span.set_attribute("gen_ai.usage.output_tokens", completion_tokens)
                record_ai_token_usage(
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    organization_id=_ACTIVE_ORG_ID.get(),
                    user_id=_ACTIVE_USER_ID.get(),
                    operation=_ACTIVE_OPERATION.get(),
                    model_name=str(settings.OPENAI_MODEL),
                )
                content = response.choices[0].message.content
                return content or ""

        enforce_org_ai_budget(_ACTIVE_ORG_ID.get())
        try:
            return str(openai_circuit_breaker.call(_raw_call))
        except AIBudgetExceededError:
            raise
        except CircuitOpenError as exc:
            logger.warning("OpenAI circuit is OPEN: %s", exc)
            raise
        except Exception as exc:
            logger.error("OpenAI call failed: %s", exc)
            raise

    @staticmethod
    def _validate_prose_input(user_input: str) -> str:
        if not isinstance(user_input, str):
            raise ValueError("Input must be a string.")
        is_dangerous, reason = InputValidator.detect_injection(user_input)
        if is_dangerous:
            raise ValueError(f"Input blocked: {reason}")
        sanitized = InputValidator.sanitize_string(user_input)
        if not sanitized:
            raise ValueError("Input cannot be empty after sanitization.")
        return sanitized

    @staticmethod
    def _validate_code_or_spec_input(user_input: str) -> str:
        if not isinstance(user_input, str):
            raise ValueError("Input must be a string.")
        is_code_dangerous, code_reason = InputValidator.validate_code_input(user_input)
        if is_code_dangerous:
            raise ValueError(f"Input blocked: {code_reason}")
        is_xss, xss_reason = InputValidator.detect_xss(user_input)
        if is_xss:
            raise ValueError(f"Input blocked: {xss_reason}")
        sanitized = InputValidator.sanitize_string(user_input)
        if not sanitized:
            raise ValueError("Input cannot be empty after sanitization.")
        return sanitized

    def suggest_task_translations(
        self,
        user_id: str,
        lang: str,
        user_input: str,
        organization_id: str | None = None,
    ) -> dict[str, Any]:
        """Generate AI-suggested EN/ES/FR translations validated via Pydantic."""
        sanitized = self._validate_prose_input(user_input)
        version = self.template_manager.get_version("task_translation")

        cache_key = _make_cache_key(
            user_id, lang, {"fn": "translate", "v": version, "q": sanitized}
        )
        cached = cache.get(cache_key)
        if cached is not None:
            record_cache_hit()
            return dict(cached)

        record_cache_miss()
        enforce_org_ai_budget(organization_id)
        prompt = self.template_manager.render("task_translation", user_input=sanitized, lang=lang)
        org_tok = _ACTIVE_ORG_ID.set(organization_id)
        usr_tok = _ACTIVE_USER_ID.set(user_id)
        op_tok = _ACTIVE_OPERATION.set("suggest_task_translations")
        try:
            raw = self._call_llm(prompt, temperature=0.3)
        finally:
            _ACTIVE_OPERATION.reset(op_tok)
            _ACTIVE_USER_ID.reset(usr_tok)
            _ACTIVE_ORG_ID.reset(org_tok)
        parsed = _safe_json_parse(raw)
        if not parsed:
            raise UpstreamAIResponseError("Empty or malformed JSON from AI provider")

        try:
            validated = TranslationSuggestionSchema.model_validate(parsed)
        except PydanticValidationError as exc:
            logger.warning("AI translation schema validation failed: %s", exc)
            raise UpstreamAIResponseError("AI response failed schema validation") from exc

        result = validated.model_dump()
        cache.set(cache_key, result, timeout=CACHE_TTL_AI)
        return result

    def evaluate_prompt_quality(
        self,
        user_id: str,
        lang: str,
        user_input: str,
        organization_id: str | None = None,
    ) -> dict[str, Any]:
        """Evaluate prompt quality and validate score/improvements via Pydantic."""
        sanitized = self._validate_prose_input(user_input)
        version = self.template_manager.get_version("prompt_evaluation")

        cache_key = _make_cache_key(user_id, lang, {"fn": "eval", "v": version, "q": sanitized})
        cached = cache.get(cache_key)
        if cached is not None:
            record_cache_hit()
            return dict(cached)

        record_cache_miss()
        enforce_org_ai_budget(organization_id)
        prompt = self.template_manager.render("prompt_evaluation", user_input=sanitized, lang=lang)
        org_tok = _ACTIVE_ORG_ID.set(organization_id)
        usr_tok = _ACTIVE_USER_ID.set(user_id)
        op_tok = _ACTIVE_OPERATION.set("evaluate_prompt_quality")
        try:
            raw = self._call_llm(prompt, temperature=0.2)
        finally:
            _ACTIVE_OPERATION.reset(op_tok)
            _ACTIVE_USER_ID.reset(usr_tok)
            _ACTIVE_ORG_ID.reset(org_tok)
        parsed = _safe_json_parse(raw)
        if not parsed:
            raise UpstreamAIResponseError("Empty or malformed JSON from AI provider")

        try:
            validated = PromptQualitySchema.model_validate(parsed)
        except PydanticValidationError as exc:
            logger.warning("AI quality schema validation failed: %s", exc)
            raise UpstreamAIResponseError("AI response failed schema validation") from exc

        result = validated.model_dump()
        cache.set(cache_key, result, timeout=CACHE_TTL_AI)
        return result

    def generate_rlhf_test_cases(
        self,
        user_id: str,
        lang: str,
        user_input: str,
        organization_id: str | None = None,
    ) -> dict[str, Any]:
        """Generate RLHF-style pytest unit tests validated via Pydantic."""
        sanitized = self._validate_code_or_spec_input(user_input)
        version = self.template_manager.get_version("rlhf_generation")

        cache_key = _make_cache_key(user_id, lang, {"fn": "rlhf", "v": version, "q": sanitized})
        cached = cache.get(cache_key)
        if cached is not None:
            record_cache_hit()
            return dict(cached)

        record_cache_miss()
        enforce_org_ai_budget(organization_id)
        prompt = self.template_manager.render("rlhf_generation", user_input=sanitized, lang=lang)
        org_tok = _ACTIVE_ORG_ID.set(organization_id)
        usr_tok = _ACTIVE_USER_ID.set(user_id)
        op_tok = _ACTIVE_OPERATION.set("generate_rlhf_test_cases")
        try:
            raw = self._call_llm(prompt, temperature=0.4)
        finally:
            _ACTIVE_OPERATION.reset(op_tok)
            _ACTIVE_USER_ID.reset(usr_tok)
            _ACTIVE_ORG_ID.reset(org_tok)
        parsed = _safe_json_parse(raw)
        if not parsed:
            raise UpstreamAIResponseError("Empty or malformed JSON from AI provider")

        try:
            validated = RLHFTestCaseSchema.model_validate(parsed)
        except PydanticValidationError as exc:
            logger.warning("AI RLHF schema validation failed: %s", exc)
            raise UpstreamAIResponseError("AI response failed schema validation") from exc

        result = validated.model_dump()
        cache.set(cache_key, result, timeout=CACHE_TTL_AI)
        return result

    def _parse_json_response(self, raw: str) -> dict[str, Any]:
        """Internal JSON parser maintained for direct unit test compatibility."""
        result = _safe_json_parse(raw)
        if not result or not isinstance(result, dict):
            raise ValueError("Unparseable JSON response from LLM")
        return result


# Singleton instance for import convenience
_ai_service = AIService()
