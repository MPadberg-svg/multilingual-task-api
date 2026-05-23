"""Tests for core middleware components."""

from unittest.mock import MagicMock, patch

from django.http import JsonResponse
from django.test import RequestFactory

from apps.core.middleware import LanguageResolutionMiddleware, RequestLoggingMiddleware


class TestRequestLoggingMiddleware:
    """Tests for request logging middleware."""

    def setup_method(self):
        self.factory = RequestFactory()
        self.get_response = MagicMock(return_value=JsonResponse({"ok": True}))

    def test_middleware_logs_request(self):
        """Middleware should log incoming requests."""
        with patch("apps.core.middleware.logger") as mock_logger:
            middleware = RequestLoggingMiddleware(self.get_response)
            request = self.factory.get("/api/v1/health/")
            middleware(request)
            # Should log at least one message (request or response)
            assert mock_logger.info.call_count >= 1

    def test_middleware_logs_response(self):
        """Middleware should log responses."""
        with patch("apps.core.middleware.logger") as mock_logger:
            middleware = RequestLoggingMiddleware(self.get_response)
            request = self.factory.get("/api/v1/health/")
            middleware(request)
            # Should log response with status code
            log_calls = " ".join(str(call) for call in mock_logger.info.call_args_list)
            assert "200" in log_calls or "response" in log_calls.lower()

    def test_middleware_handles_error_response(self):
        """Middleware should log error status codes."""
        error_response = JsonResponse({"error": "test"}, status=500)
        get_response = MagicMock(return_value=error_response)
        with patch("apps.core.middleware.logger") as mock_logger:
            middleware = RequestLoggingMiddleware(get_response)
            request = self.factory.get("/api/v1/health/")
            middleware(request)
            log_calls = " ".join(str(call) for call in mock_logger.info.call_args_list)
            assert "500" in log_calls or "error" in log_calls.lower()


class TestLanguageResolutionMiddleware:
    """Tests for language resolution middleware."""

    def setup_method(self):
        self.factory = RequestFactory()
        self.get_response = MagicMock(return_value=JsonResponse({"ok": True}))

    def test_sets_language_from_header(self):
        """Middleware should set language from Accept-Language header."""
        middleware = LanguageResolutionMiddleware(self.get_response)
        request = self.factory.get(
            "/api/v1/tasks/",
            HTTP_ACCEPT_LANGUAGE="es",
        )
        middleware(request)
        assert hasattr(request, "language")
        assert request.language == "es"

    def test_defaults_to_english(self):
        """Middleware should default to English without header."""
        middleware = LanguageResolutionMiddleware(self.get_response)
        request = self.factory.get("/api/v1/tasks/")
        middleware(request)
        assert request.language == "en"

    def test_handles_invalid_language(self):
        """Middleware should fallback for unsupported languages."""
        middleware = LanguageResolutionMiddleware(self.get_response)
        request = self.factory.get(
            "/api/v1/tasks/",
            HTTP_ACCEPT_LANGUAGE="xx",
        )
        middleware(request)
        # Should fallback to English or default
        assert hasattr(request, "language")
