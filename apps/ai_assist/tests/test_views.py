"""Integration tests for AI Assist API endpoints."""

import pytest
from unittest.mock import patch
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

User = get_user_model()


@pytest.mark.django_db
class TestAIAssistViews:

    def setup_method(self):
        self.user = User.objects.create_user(
            email="aiview@example.com",
            password="testpass123",
        )
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    # ── Auth ──────────────────────────────────────────────────────────

    def test_suggest_task_unauthenticated_returns_401(self):
        response = APIClient().post(
            "/api/v1/ai/suggest-task/",
            {"description": "test"},
            format="json",
        )
        assert response.status_code == 401

    def test_evaluate_quality_unauthenticated_returns_401(self):
        response = APIClient().post(
            "/api/v1/ai/evaluate-quality/",
            {"prompt": "test"},
            format="json",
        )
        assert response.status_code == 401

    def test_generate_test_cases_unauthenticated_returns_401(self):
        response = APIClient().post(
            "/api/v1/ai/generate-test-cases/",
            {"task_description": "test"},
            format="json",
        )
        assert response.status_code == 401

    # ── Input validation ──────────────────────────────────────────────

    def test_suggest_task_empty_description_returns_400(self):
        response = self.client.post(
            "/api/v1/ai/suggest-task/",
            {"description": ""},
            format="json",
        )
        assert response.status_code == 400

    def test_suggest_task_sql_injection_blocked(self):
        response = self.client.post(
            "/api/v1/ai/suggest-task/",
            {"description": "'; DROP TABLE tasks; --"},
            format="json",
        )
        assert response.status_code in (400, 422)

    def test_suggest_task_xss_blocked(self):
        response = self.client.post(
            "/api/v1/ai/suggest-task/",
            {"description": "<script>alert('xss')</script>"},
            format="json",
        )
        assert response.status_code in (400, 422)

    # ── Happy path (mocked LLM) ───────────────────────────────────────

    @patch("apps.ai_assist.services.AIService._call_llm")
    def test_suggest_task_returns_200(self, mock_llm):
        mock_llm.return_value = '{"en": "Title", "es": "Título", "fr": "Titre"}'
        response = self.client.post(
            "/api/v1/ai/suggest-task/",
            {"description": "Review quarterly metrics for annotation"},
            format="json",
        )
        assert response.status_code in (200, 201)

    @patch("apps.ai_assist.services.AIService._call_llm")
    def test_evaluate_quality_returns_200(self, mock_llm):
        mock_llm.return_value = '{"score": 8, "feedback": "Clear prompt"}'
        response = self.client.post(
            "/api/v1/ai/evaluate-quality/",
            {"prompt": "Label the sentiment of this tweet as positive or negative."},
            format="json",
        )
        assert response.status_code in (200, 201)

    @patch("apps.ai_assist.services.AIService._call_llm")
    def test_generate_test_cases_returns_200(self, mock_llm):
        mock_llm.return_value = '[{"input": "test", "expected": "positive"}]'
        response = self.client.post(
            "/api/v1/ai/generate-test-cases/",
            {"task_description": "Annotate images of outdoor scenes"},
            format="json",
        )
        assert response.status_code in (200, 201)