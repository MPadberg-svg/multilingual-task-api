"""Tests for core middleware components."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from django.contrib.auth import get_user_model
from django.http import HttpResponse, JsonResponse
from django.test import RequestFactory

from apps.core.middleware import (
    ContentSecurityPolicyMiddleware,
    CorrelationIdMiddleware,
    LanguageResolutionMiddleware,
    RequestLoggingMiddleware,
    TenantMiddleware,
    TenantPermissionMiddleware,
)
from apps.core.models import Organization, OrganizationMember
from apps.tasks.models import Task

User = get_user_model()


@pytest.fixture
def factory() -> RequestFactory:
    return RequestFactory()


@pytest.fixture
def get_response():
    return MagicMock(return_value=JsonResponse({"ok": True}))


class TestRequestLoggingMiddleware:
    def test_middleware_logs_request_and_response(self, factory, get_response):
        with patch("apps.core.middleware.logger") as mock_logger:
            middleware = RequestLoggingMiddleware(get_response)
            request = factory.get("/api/v1/health/?lang=en")
            middleware(request)
            assert mock_logger.info.call_count >= 2

    def test_middleware_logs_error_response(self, factory):
        error_response = JsonResponse({"error": "test"}, status=500)
        get_response = MagicMock(return_value=error_response)
        with patch("apps.core.middleware.logger") as mock_logger:
            middleware = RequestLoggingMiddleware(get_response)
            request = factory.get("/api/v1/health/")
            middleware(request)
            log_calls = " ".join(str(call) for call in mock_logger.info.call_args_list)
            assert "500" in log_calls

    def test_get_client_ip_prefers_forwarded_header(self, factory, get_response):
        middleware = RequestLoggingMiddleware(get_response)
        request = factory.get("/api/v1/health/", HTTP_X_FORWARDED_FOR="1.1.1.1, 2.2.2.2")
        assert middleware._get_client_ip(request) == "1.1.1.1"

    def test_get_client_ip_uses_remote_addr(self, factory, get_response):
        middleware = RequestLoggingMiddleware(get_response)
        request = factory.get("/api/v1/health/")
        request.META["REMOTE_ADDR"] = "9.9.9.9"
        assert middleware._get_client_ip(request) == "9.9.9.9"


class TestLanguageResolutionMiddleware:
    def test_query_param_takes_priority(self, factory, get_response):
        middleware = LanguageResolutionMiddleware(get_response)
        request = factory.get("/api/v1/tasks/?lang=fr", HTTP_ACCEPT_LANGUAGE="es")
        middleware.process_request(request)
        assert request.language == "fr"
        assert request.lang == "fr"

    def test_sets_language_from_header(self, factory, get_response):
        middleware = LanguageResolutionMiddleware(get_response)
        request = factory.get("/api/v1/tasks/", HTTP_ACCEPT_LANGUAGE="es,fr;q=0.9")
        middleware.process_request(request)
        assert request.language == "es"

    def test_defaults_to_english(self, factory, get_response):
        middleware = LanguageResolutionMiddleware(get_response)
        request = factory.get("/api/v1/tasks/")
        middleware.process_request(request)
        assert request.language == "en"

    def test_falls_back_to_english_for_long_values(self, factory, get_response):
        middleware = LanguageResolutionMiddleware(get_response)
        request = factory.get("/api/v1/tasks/", HTTP_ACCEPT_LANGUAGE="abcdefghijklmnop")
        middleware.process_request(request)
        assert request.language == "en"


class TestCorrelationIdMiddleware:
    def test_uses_existing_correlation_id_header(self, factory, get_response):
        middleware = CorrelationIdMiddleware(get_response)
        request = factory.get("/api/v1/health/", HTTP_X_CORRELATION_ID="abc-123")
        middleware.process_request(request)
        assert request.correlation_id == "abc-123"

    def test_generates_correlation_id_when_missing(self, factory, get_response):
        middleware = CorrelationIdMiddleware(get_response)
        request = factory.get("/api/v1/health/")
        middleware.process_request(request)
        assert request.correlation_id

    def test_process_response_sets_header(self, factory, get_response):
        middleware = CorrelationIdMiddleware(get_response)
        request = factory.get("/api/v1/health/")
        request.correlation_id = "resp-cid"
        response = middleware.process_response(request, HttpResponse("ok"))
        assert response["X-Correlation-Id"] == "resp-cid"


class TestContentSecurityPolicyMiddleware:
    def test_adds_security_headers(self, factory, get_response):
        middleware = ContentSecurityPolicyMiddleware(get_response)
        request = factory.get("/api/v1/health/")
        response = middleware.process_response(request, HttpResponse("ok"))
        assert "default-src 'self'" in response["Content-Security-Policy"]
        assert response["Referrer-Policy"] == "strict-origin-when-cross-origin"
        assert response["Permissions-Policy"] == "geolocation=(), microphone=(), camera=()"


@pytest.mark.django_db
class TestTenantMiddleware:
    def test_no_org_header_sets_none_context(self, factory, get_response):
        middleware = TenantMiddleware(get_response)
        request = factory.get("/api/v1/tasks/")
        request.user = User.objects.create_user(email="none@example.com", password="pass1234")
        middleware.process_request(request)
        assert request.organization is None
        assert request.membership_role is None

    def test_invalid_org_id_sets_none_context(self, factory, get_response):
        middleware = TenantMiddleware(get_response)
        request = factory.get("/api/v1/tasks/", HTTP_X_ORGANIZATION_ID="invalid")
        request.user = User.objects.create_user(email="invalid@example.com", password="pass1234")
        middleware.process_request(request)
        assert request.organization is None
        assert request.membership_role is None

    def test_valid_org_and_membership_populates_context(self, factory, get_response):
        middleware = TenantMiddleware(get_response)
        user = User.objects.create_user(email="member@example.com", password="pass1234")
        org = Organization.objects.create(name="Org A", slug="org-a")
        OrganizationMember.objects.create(organization=org, user=user, role="admin")
        request = factory.get("/api/v1/tasks/", HTTP_X_ORGANIZATION_ID=str(org.id))
        request.user = user
        middleware.process_request(request)
        assert request.organization == org
        assert request.membership_role == "admin"

    def test_missing_membership_sets_none_context(self, factory, get_response):
        middleware = TenantMiddleware(get_response)
        user = User.objects.create_user(email="nomember@example.com", password="pass1234")
        org = Organization.objects.create(name="Org B", slug="org-b")
        request = factory.get("/api/v1/tasks/", HTTP_X_ORGANIZATION_ID=str(org.id))
        request.user = user
        middleware.process_request(request)
        assert request.organization is None
        assert request.membership_role is None

    def test_process_response_passthrough(self, factory, get_response):
        middleware = TenantMiddleware(get_response)
        request = factory.get("/api/v1/tasks/")
        response = HttpResponse("ok")
        assert middleware.process_response(request, response) is response


@pytest.mark.django_db
class TestTenantPermissionMiddleware:
    def test_non_mutating_method_allows(self, factory, get_response):
        middleware = TenantPermissionMiddleware(get_response)
        request = factory.get("/api/v1/tasks/")
        assert middleware.process_view(request, None, (), {}) is None

    def test_mutating_without_organization_allows(self, factory, get_response):
        middleware = TenantPermissionMiddleware(get_response)
        request = factory.post("/api/v1/tasks/")
        request.organization = None
        assert middleware.process_view(request, None, (), {}) is None

    def test_insufficient_role_returns_403(self, factory, get_response):
        middleware = TenantPermissionMiddleware(get_response)
        org = Organization.objects.create(name="Org C", slug="org-c", max_tasks=100)
        request = factory.post("/api/v1/tasks/")
        request.organization = org
        request.membership_role = "viewer"
        response = middleware.process_view(request, None, (), {})
        assert response.status_code == 403
        assert b"Insufficient permissions" in response.content

    def test_plan_limit_exceeded_returns_403(self, factory, get_response):
        middleware = TenantPermissionMiddleware(get_response)
        user = User.objects.create_user(email="limit@example.com", password="pass1234")
        org = Organization.objects.create(name="Org D", slug="org-d", max_tasks=1)
        Task.objects.create(user=user, organization=org, status="pending", is_active=True)
        request = factory.post("/api/v1/tasks/")
        request.organization = org
        request.membership_role = "admin"
        response = middleware.process_view(request, None, (), {})
        assert response.status_code == 403
        assert b"Plan limit exceeded" in response.content

    def test_admin_with_capacity_allows(self, factory, get_response):
        middleware = TenantPermissionMiddleware(get_response)
        org = Organization.objects.create(name="Org E", slug="org-e", max_tasks=10)
        request = factory.post("/api/v1/tasks/")
        request.organization = org
        request.membership_role = "owner"
        assert middleware.process_view(request, None, (), {}) is None
