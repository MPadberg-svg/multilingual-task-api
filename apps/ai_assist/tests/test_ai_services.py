"""Unit tests for the AI Assistance service layer.

All OpenAI API calls are mocked to avoid external network dependencies.
Tests cover JSON response parsing, translation suggestion, prompt quality
evaluation, RLHF test case generation, security hardening, circuit breaker
resilience, and rate limiting.
"""

import json
from unittest.mock import Mock, patch

from django.test import TestCase, override_settings

import pytest

from apps.ai_assist.services import AIService

# =============================================================================
# _parse_json_response
# =============================================================================


class TestParseJsonResponse(TestCase):
    """Validate the JSON sanitisation helper."""

    @override_settings(
        OPENAI_API_KEY="test-key",
        OPENAI_MODEL="gpt-4o-mini",
        OPENAI_MAX_TOKENS=2000,
        OPENAI_TEMPERATURE=0.7,
    )
    def test_clean_json_parsing(self):
        """Plain JSON should parse without modification."""
        service = AIService()
        result = service._parse_json_response('{"key": "value"}')
        assert result == {"key": "value"}

    @override_settings(
        OPENAI_API_KEY="test-key",
        OPENAI_MODEL="gpt-4o-mini",
        OPENAI_MAX_TOKENS=2000,
        OPENAI_TEMPERATURE=0.7,
    )
    def test_markdown_fence_stripping(self):
        """Markdown fenced blocks should be stripped before parsing."""
        service = AIService()
        result = service._parse_json_response('```json\n{"key": "value"}\n```')
        assert result == {"key": "value"}

    @override_settings(
        OPENAI_API_KEY="test-key",
        OPENAI_MODEL="gpt-4o-mini",
        OPENAI_MAX_TOKENS=2000,
        OPENAI_TEMPERATURE=0.7,
    )
    def test_trailing_comma_handling(self):
        """Trailing commas before closing braces should be removed."""
        service = AIService()
        result = service._parse_json_response('{"key": "value",}')
        assert result == {"key": "value"}

    @override_settings(
        OPENAI_API_KEY="test-key",
        OPENAI_MODEL="gpt-4o-mini",
        OPENAI_MAX_TOKENS=2000,
        OPENAI_TEMPERATURE=0.7,
    )
    def test_invalid_json_raises_valueerror(self):
        """Non-JSON input must raise ``ValueError``."""
        service = AIService()
        with pytest.raises(ValueError):
            service._parse_json_response("not json")


# =============================================================================
# suggest_task_translations
# =============================================================================


class TestSuggestTaskTranslations(TestCase):
    """Validate the task translation endpoint logic."""

    @override_settings(OPENAI_API_KEY="test-key")
    @patch("openai.OpenAI")
    def test_en_es_fr_structure(self, mock_openai_cls):
        """Response must contain ``en``, ``es``, ``fr`` with title/description."""
        mock_client = Mock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = Mock(
            choices=[
                Mock(
                    message=Mock(
                        content=json.dumps(
                            {
                                "en": {"title": "T", "description": "D"},
                                "es": {"title": "T", "description": "D"},
                                "fr": {"title": "T", "description": "D"},
                            }
                        )
                    )
                )
            ]
        )

        service = AIService()
        result = service.suggest_task_translations("user-1", "en", "test")

        assert "en" in result and "es" in result and "fr" in result
        assert "title" in result["en"] and "description" in result["en"]

    @override_settings(OPENAI_API_KEY="test-key")
    @patch("apps.ai_assist.services.cache")  # FIXED: patch cache to verify deduplication
    @patch("openai.OpenAI")
    def test_caching_deduplication(self, mock_openai_cls, mock_cache):
        """Identical inputs must hit cache and call OpenAI only once."""
        mock_client = Mock()
        # FIXED: Return the SAME mock client instance so call_count accumulates
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = Mock(
            choices=[
                Mock(
                    message=Mock(
                        content=json.dumps(
                            {
                                "en": {"title": "T", "description": "D"},
                                "es": {"title": "T", "description": "D"},
                                "fr": {"title": "T", "description": "D"},
                            }
                        )
                    )
                )
            ]
        )

        # First call: cache miss → calls OpenAI
        mock_cache.get.return_value = None
        service = AIService()
        r1 = service.suggest_task_translations("user-1", "en", "same")

        # Second call: cache hit → returns cached value, no OpenAI call
        mock_cache.get.return_value = r1
        r2 = service.suggest_task_translations("user-1", "en", "same")

        # OpenAI should only be called ONCE
        assert mock_client.chat.completions.create.call_count == 1
        assert r1 == r2
        # Cache.set should be called once with the result
        mock_cache.set.assert_called_once()


# =============================================================================
# evaluate_prompt_quality
# =============================================================================


class TestEvaluatePromptQuality(TestCase):
    """Validate the prompt quality evaluation logic."""

    @override_settings(OPENAI_API_KEY="test-key")
    @patch("openai.OpenAI")
    def test_score_range_and_type(self, mock_openai_cls):
        """Score must be an integer in [0, 100]; improvements list; analysis str."""
        mock_client = Mock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = Mock(
            choices=[
                Mock(
                    message=Mock(
                        content=json.dumps(
                            {
                                "score": 85,
                                "improvements": ["Add constraints"],
                                "analysis": "Good but needs work",
                            }
                        )
                    )
                )
            ]
        )

        service = AIService()
        result = service.evaluate_prompt_quality("user-1", "en", "test prompt")

        assert isinstance(result["score"], int)
        assert 0 <= result["score"] <= 100
        assert isinstance(result["improvements"], list)
        assert isinstance(result["analysis"], str)


# =============================================================================
# generate_rlhf_test_cases
# =============================================================================


class TestGenerateRlhfTestCases(TestCase):
    """Validate the RLHF test case generation logic."""

    @override_settings(OPENAI_API_KEY="test-key")
    @patch("openai.OpenAI")
    def test_jsonl_structure(self, mock_openai_cls):
        """Response must contain instruction, input, output, metadata with edge_cases."""
        mock_client = Mock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = Mock(
            choices=[
                Mock(
                    message=Mock(
                        content=json.dumps(
                            {
                                "instruction": "Write test",
                                "input": "def add(a,b): return a+b",
                                "output": "assert add(2,3)==5",
                                "metadata": {
                                    "language": "python",
                                    "framework": "pytest",
                                    "edge_cases": ["negative numbers"],
                                },
                            }
                        )
                    )
                )
            ]
        )

        service = AIService()
        result = service.generate_rlhf_test_cases("user-1", "en", "def add(a,b): return a+b")

        assert "instruction" in result
        assert "input" in result
        assert "output" in result
        assert "metadata" in result
        assert "edge_cases" in result["metadata"]


# =============================================================================
# AI Security Tests — Input Validation
# =============================================================================


class TestAISecurity(TestCase):
    """Validate that AIService blocks malicious input before it reaches the LLM."""

    @override_settings(
        OPENAI_API_KEY="test-key",
        OPENAI_MODEL="gpt-4o-mini",
        OPENAI_MAX_TOKENS=2000,
        OPENAI_TEMPERATURE=0.7,
    )
    def test_sql_injection_is_blocked(self):
        """AI service must reject SQL injection patterns with ValueError."""
        service = AIService()
        with self.assertRaises(ValueError) as ctx:
            service.suggest_task_translations(
                user_id="test-user",
                lang="en",
                user_input="'; DROP TABLE tasks; --",
            )
        self.assertIn("Input blocked", str(ctx.exception))

    @override_settings(
        OPENAI_API_KEY="test-key",
        OPENAI_MODEL="gpt-4o-mini",
        OPENAI_MAX_TOKENS=2000,
        OPENAI_TEMPERATURE=0.7,
    )
    def test_xss_input_is_blocked(self):
        """AI service must reject XSS patterns with ValueError."""
        service = AIService()
        with self.assertRaises(ValueError) as ctx:
            service.suggest_task_translations(
                user_id="test-user",
                lang="en",
                user_input="<script>document.cookie='stolen'</script>",
            )
        self.assertIn("Input blocked", str(ctx.exception))


# =============================================================================
# Circuit Breaker Tests
# =============================================================================


class TestCircuitBreaker(TestCase):
    """Validate circuit breaker state transitions and resilience."""

    def test_circuit_breaker_is_closed_initially(self):
        """Circuit breaker must start in CLOSED state."""
        from apps.ai_assist.circuit_breaker import CircuitBreaker, CircuitState

        cb = CircuitBreaker(name="test", failure_threshold=5, recovery_timeout=60)
        self.assertEqual(cb.state, CircuitState.CLOSED)
        self.assertEqual(cb._failure_count, 0)

    def test_circuit_breaker_opens_after_threshold_failures(self):
        """Circuit must open after N consecutive failures."""
        from apps.ai_assist.circuit_breaker import CircuitBreaker, CircuitOpenError, CircuitState

        cb = CircuitBreaker(name="test", failure_threshold=3, recovery_timeout=60)

        def bad_func():
            raise ValueError("API down")

        # Trigger 3 failures to reach threshold
        for _ in range(3):
            with self.assertRaises(ValueError):
                cb.call(bad_func)

        self.assertEqual(cb.state, CircuitState.OPEN)

        # Next call must raise CircuitOpenError immediately
        with self.assertRaises(CircuitOpenError):
            cb.call(bad_func)

    def test_circuit_breaker_half_open_after_timeout(self):
        """Circuit must transition to HALF_OPEN after recovery_timeout."""
        from apps.ai_assist.circuit_breaker import CircuitBreaker, CircuitState

        cb = CircuitBreaker(name="test", failure_threshold=2, recovery_timeout=0)

        def bad_func():
            raise ValueError("API down")

        # Open the circuit
        for _ in range(2):
            with self.assertRaises(ValueError):
                cb.call(bad_func)

        # With recovery_timeout=0, checking state triggers immediate transition
        # to HALF_OPEN because (now - last_failure_time) >= 0 is always true
        self.assertEqual(cb.state, CircuitState.HALF_OPEN)

        # A successful call in HALF_OPEN should close the circuit
        result = cb.call(lambda: "recovery")
        self.assertEqual(result, "recovery")
        self.assertEqual(cb.state, CircuitState.CLOSED)


# =============================================================================
# Rate Limiting Tests
# =============================================================================


@override_settings(
    CACHES={
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        }
    }
)
class TestRateLimiting(TestCase):
    """Validate that AI endpoints enforce rate limits."""

    @patch("openai.OpenAI")
    def test_ai_service_respects_rate_limit(self, mock_openai_cls):
        """AI endpoint must throttle excessive requests."""
        from django.contrib.auth import get_user_model
        from django.core.cache import cache
        from django.urls import reverse

        from rest_framework.test import APIClient

        User = get_user_model()
        client = APIClient()

        user = User.objects.create_user(
            email="ratelimit@example.com",
            password="testpass123",
        )
        client.force_authenticate(user=user)

        # Mock OpenAI to return valid JSON quickly (no real API calls)
        mock_client = Mock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = Mock(
            choices=[
                Mock(
                    message=Mock(
                        content=json.dumps(
                            {
                                "en": {"title": "T", "description": "D"},
                                "es": {"title": "T", "description": "D"},
                                "fr": {"title": "T", "description": "D"},
                            }
                        )
                    )
                )
            ]
        )

        # Clear any existing throttle cache for this user
        cache.delete(f"mltask:throttle:ai_assist_burst:{user.pk}")
        cache.delete(f"mltask:throttle:ai_assist:{user.pk}")

        # Make requests up to the burst limit (5/min per views.py)
        for i in range(5):
            response = client.post(
                reverse("suggest-task"),
                {"description": f"Task {i}", "lang": "en"},
                format="json",
            )
            self.assertEqual(response.status_code, 200)

        # The 6th request should be throttled (429)
        response = client.post(
            reverse("suggest-task"),
            {"description": "Over the limit", "lang": "en"},
            format="json",
        )
        self.assertEqual(response.status_code, 429)
