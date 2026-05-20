"""AI Assist service layer with security hardening.

Provides ``AIService`` for LLM-backed task operations including translation
suggestions, prompt quality evaluation, and RLHF test-case generation.
All public methods validate and sanitize user input before processing.

Cache keys follow the project convention:
    ``mltask:ai:{user_id}:{lang}:{sha256_hash}``
"""

import hashlib
import json
import logging
from typing import Any

from django.conf import settings
from django.core.cache import cache

from apps.ai_assist.prompt_templates import PromptTemplateManager
from apps.core.security import InputValidator

logger = logging.getLogger(__name__)

CACHE_TTL_AI = 3600  # seconds


def _make_cache_key(user_id: str, lang: str, params: dict) -> str:
    """Generate a deterministic SHA256 cache key.

    Args:
        user_id: UUID of the requesting user.
        lang: Resolved language code.
        params: Serializable parameters dict.

    Returns:
        Cache key string in ``mltask:ai:{user_id}:{lang}:{hash}`` format.
    """
    payload = json.dumps(params, sort_keys=True, ensure_ascii=True)
    digest = hashlib.sha256(payload.encode()).hexdigest()[:16]
    return f"mltask:ai:{user_id}:{lang}:{digest}"


def _safe_json_parse(raw: str) -> dict[str, Any]:
    """Fail-safe JSON parser with fallback to empty dict.

    Args:
        raw: Raw string from LLM response.

    Returns:
        Parsed dict or empty dict on failure.
    """
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError) as exc:
        logger.warning("JSON parse failed: %s", exc)
        return {}


class AIService:
    """Orchestrates LLM calls with caching, security validation, and resilience.

    Attributes:
        client: OpenAI client instance (lazy initialised).
        template_manager: PromptTemplateManager for versioned prompts.
    """

    def __init__(self) -> None:
        self._client = None
        self.template_manager = PromptTemplateManager()

    @property
    def client(self):
        """Lazy OpenAI client initialisation."""
        if self._client is None:
            import openai
            self._client = openai.OpenAI(api_key=settings.OPENAI_API_KEY)
        return self._client

    def suggest_task_translations(
        self,
        user_id: str,
        lang: str,
        user_input: str,
    ) -> dict[str, Any]:
        """Generate AI-suggested translations for a task.

        Args:
            user_id: UUID of the requesting user.
            lang: Target language code.
            user_input: Raw user description or title.

        Returns:
            Dict with suggested translations and metadata.

        Raises:
            ValueError: If input contains dangerous patterns.
        """
        is_dangerous, reason = InputValidator.detect_injection(user_input)
        if is_dangerous:
            raise ValueError(f"Input blocked: {reason}")
        sanitized = InputValidator.sanitize_string(user_input)

        cache_key = _make_cache_key(user_id, lang, {"fn": "translate", "q": sanitized})
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

        prompt = self.template_manager.render("task_translation", lang=lang, user_input=sanitized)
        response = self.client.chat.completions.create(
            model=settings.OPENAI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
        )
        result = _safe_json_parse(response.choices[0].message.content)
        cache.set(cache_key, result, timeout=CACHE_TTL_AI)
        return result

    def evaluate_prompt_quality(
        self,
        user_id: str,
        lang: str,
        user_input: str,
    ) -> dict[str, Any]:
        """Evaluate the quality of a user-provided prompt.

        Args:
            user_id: UUID of the requesting user.
            lang: Target language code.
            user_input: Raw prompt text.

        Returns:
            Dict with quality score and improvement suggestions.

        Raises:
            ValueError: If input contains dangerous patterns.
        """
        is_dangerous, reason = InputValidator.detect_injection(user_input)
        if is_dangerous:
            raise ValueError(f"Input blocked: {reason}")
        sanitized = InputValidator.sanitize_string(user_input)

        cache_key = _make_cache_key(user_id, lang, {"fn": "eval", "q": sanitized})
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

        prompt = self.template_manager.render("prompt_evaluation", lang=lang, user_input=sanitized)
        response = self.client.chat.completions.create(
            model=settings.OPENAI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
        )
        result = _safe_json_parse(response.choices[0].message.content)
        cache.set(cache_key, result, timeout=CACHE_TTL_AI)
        return result

    def generate_rlhf_test_cases(
        self,
        user_id: str,
        lang: str,
        user_input: str,
    ) -> dict[str, Any]:
        """Generate RLHF-style test cases from a task description.

        Args:
            user_id: UUID of the requesting user.
            lang: Target language code.
            user_input: Raw task description.

        Returns:
            Dict with generated test cases.

        Raises:
            ValueError: If input contains dangerous patterns.
        """
        is_dangerous, reason = InputValidator.detect_injection(user_input)
        if is_dangerous:
            raise ValueError(f"Input blocked: {reason}")
        sanitized = InputValidator.sanitize_string(user_input)

        cache_key = _make_cache_key(user_id, lang, {"fn": "rlhf", "q": sanitized})
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

        prompt = self.template_manager.render("rlhf_generation", lang=lang, user_input=sanitized)
        response = self.client.chat.completions.create(
            model=settings.OPENAI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.4,
        )
        result = _safe_json_parse(response.choices[0].message.content)
        cache.set(cache_key, result, timeout=CACHE_TTL_AI)
        return result