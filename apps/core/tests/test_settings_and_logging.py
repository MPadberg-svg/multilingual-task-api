"""Tests for production settings hardening, proxy IP extraction, and log redaction."""

from __future__ import annotations

import importlib
import json
import sys
from typing import Any
from unittest.mock import MagicMock, patch

from django.core.exceptions import ImproperlyConfigured
from django.http import JsonResponse
from django.test import RequestFactory, override_settings

import pytest

from apps.core.middleware import RequestLoggingMiddleware


def _load_fresh_production_settings() -> Any:
    """Reload base and production settings cleanly from current environment."""
    import config.settings.base as base_mod

    importlib.reload(base_mod)
    sys.modules.pop("config.settings.production", None)
    return importlib.import_module("config.settings.production")


class TestProductionSettingsHardening:
    """Verify security invariants in config.settings.production."""

    @pytest.fixture(autouse=True)
    def _restore_base_settings(self, monkeypatch: pytest.MonkeyPatch) -> Any:
        yield
        monkeypatch.setenv(
            "SECRET_KEY",
            "test-secret-key-not-for-production-0123456789abcdef",
        )
        import config.settings.base as base_mod

        importlib.reload(base_mod)
        sys.modules.pop("config.settings.production", None)

    def test_production_rejects_placeholder_secret_key(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SECRET_KEY", "change-me-in-production")
        monkeypatch.setenv("ALLOWED_HOSTS", "api.example.com")
        with pytest.raises(ImproperlyConfigured, match="SECRET_KEY"):
            _load_fresh_production_settings()

    def test_production_rejects_short_secret_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SECRET_KEY", "too-short-secret")
        monkeypatch.setenv("ALLOWED_HOSTS", "api.example.com")
        with pytest.raises(ImproperlyConfigured, match="SECRET_KEY"):
            _load_fresh_production_settings()

    def test_production_configures_alb_proxy_ssl_and_single_log_handler(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(
            "SECRET_KEY",
            "prod-valid-random-secret-key-0123456789abcdef0123456789abcdef",
        )
        monkeypatch.setenv("ALLOWED_HOSTS", "api.example.com")
        prod_mod = _load_fresh_production_settings()

        assert prod_mod.DEBUG is False
        assert prod_mod.SECURE_PROXY_SSL_HEADER == ("HTTP_X_FORWARDED_PROTO", "https")
        assert any("health" in pattern for pattern in prod_mod.SECURE_REDIRECT_EXEMPT)
        for logger_name in ("apps", "django", "django.server", "celery"):
            assert prod_mod.LOGGING["loggers"][logger_name]["handlers"] == ["console"]
        assert prod_mod.LOGGING["handlers"]["console"]["formatter"] == "json"


class TestClientIpAndQueryRedaction:
    """Verify spoof-resistant IP extraction and sensitive query param redaction."""

    def setup_method(self) -> None:
        self.factory = RequestFactory()
        self.get_response = MagicMock(return_value=JsonResponse({"ok": True}))

    @override_settings(TRUSTED_PROXY_COUNT=0)
    def test_ignores_spoofed_xff_when_no_trusted_proxies(self) -> None:
        request = self.factory.get(
            "/api/v1/live/",
            REMOTE_ADDR="198.51.100.25",
            HTTP_X_FORWARDED_FOR="1.2.3.4",
        )
        assert RequestLoggingMiddleware._get_client_ip(request) == "198.51.100.25"

    @override_settings(TRUSTED_PROXY_COUNT=1)
    def test_extracts_rightmost_trusted_hop_behind_alb(self) -> None:
        request = self.factory.get(
            "/api/v1/live/",
            REMOTE_ADDR="10.0.1.15",
            HTTP_X_FORWARDED_FOR="1.2.3.4, 203.0.113.50",
        )
        assert RequestLoggingMiddleware._get_client_ip(request) == "203.0.113.50"

    def test_redacts_sensitive_query_params_in_request_logs(self) -> None:
        middleware = RequestLoggingMiddleware(self.get_response)
        request = self.factory.get(
            "/api/v1/tasks/?lang=es&token=eyJhbGciOiJIUzI1NiJ9&api_key=sk-secret",
            REMOTE_ADDR="127.0.0.1",
        )
        with patch("apps.core.middleware.logger") as mock_logger:
            middleware(request)
            first_payload = json.loads(mock_logger.info.call_args_list[0][0][0])

        assert "eyJhbGciOiJIUzI1NiJ9" not in first_payload["query_string"]
        assert "sk-secret" not in first_payload["query_string"]
        assert "lang=es" in first_payload["query_string"]
        assert "REDACTED" in first_payload["query_string"]
