"""Unit tests for the AI Assistance service layer.

All OpenAI API calls are mocked to avoid external network dependencies.
Tests cover JSON response parsing, translation suggestion, prompt quality
evaluation, and RLHF test case generation.
"""

import json
from unittest.mock import Mock, patch

import pytest
from django.test import override_settings

from apps.ai_assist.services import AIService, _ai_service


# =============================================================================
# _parse_json_response
# =============================================================================

@override_settings(
    OPENAI_API_KEY="test-key",
    OPENAI_MODEL="gpt-4o-mini",
    OPENAI_MAX_TOKENS=2000,
    OPENAI_TEMPERATURE=0.7,
)
class TestParseJsonResponse:
    """Validate the JSON sanitisation helper."""

    def test_clean_json_parsing(self):
        """Plain JSON should parse without modification."""
        service = AIService()
        result = service._parse_json_response('{"key": "value"}')
        assert result == {"key": "value"}

    def test_markdown_fence_stripping(self):
        """Markdown fenced blocks should be stripped before parsing."""
        service = AIService()
        result = service._parse_json_response(
            "```json\n{\"key\": \"value\"}\n```"
        )
        assert result == {"key": "value"}

    def test_trailing_comma_handling(self):
        """Trailing commas before closing braces should be removed."""
        service = AIService()
        result = service._parse_json_response('{"key": "value",}')
        assert result == {"key": "value"}

    def test_invalid_json_raises_valueerror(self):
        """Non-JSON input must raise ``ValueError``."""
        service = AIService()
        with pytest.raises(ValueError):
            service._parse_json_response("not json")


# =============================================================================
# suggest_task_translations
# =============================================================================

@override_settings(OPENAI_API_KEY="test-key")
class TestSuggestTaskTranslations:
    """Validate the task translation endpoint logic."""

    @patch("apps.ai_assist.services.OpenAI")
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
        result = service.suggest_task_translations("test")

        assert "en" in result and "es" in result and "fr" in result
        assert "title" in result["en"] and "description" in result["en"]

    @patch("apps.ai_assist.services.OpenAI")
    def test_caching_deduplication(self, mock_openai_cls):
        """Identical inputs must hit cache and call OpenAI only once."""
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
        r1 = service.suggest_task_translations("same")
        r2 = service.suggest_task_translations("same")

        assert mock_client.chat.completions.create.call_count == 1
        assert r1 == r2


# =============================================================================
# evaluate_prompt_quality
# =============================================================================

@override_settings(OPENAI_API_KEY="test-key")
class TestEvaluatePromptQuality:
    """Validate the prompt quality evaluation logic."""

    @patch("apps.ai_assist.services.OpenAI")
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
        result = service.evaluate_prompt_quality("test prompt")

        assert isinstance(result["score"], int)
        assert 0 <= result["score"] <= 100
        assert isinstance(result["improvements"], list)
        assert isinstance(result["analysis"], str)


# =============================================================================
# generate_rlhf_test_cases
# =============================================================================

@override_settings(OPENAI_API_KEY="test-key")
class TestGenerateRlhfTestCases:
    """Validate the RLHF test case generation logic."""

    @patch("apps.ai_assist.services.OpenAI")
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
        result = service.generate_rlhf_test_cases("def add(a,b): return a+b")

        assert "instruction" in result
        assert "input" in result
        assert "output" in result
        assert "metadata" in result
        assert "edge_cases" in result["metadata"]