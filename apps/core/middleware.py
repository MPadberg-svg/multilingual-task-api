"""Core middleware for language resolution, correlation IDs, security, and tenancy.

Provides:
    - ``LanguageResolutionMiddleware``: Extracts ``?lang=`` → ``Accept-Language`` → ``en``.
    - ``CorrelationIdMiddleware``: Attaches ``X-Correlation-Id`` to requests/responses.
    - ``RequestLoggingMiddleware``: Emits structured JSON logs with redacted params.
    - ``ContentSecurityPolicyMiddleware``: Injects security headers on every response.
    - ``TenantMiddleware``: Resolves JWT/session user, organization, and membership role.
    - ``TenantPermissionMiddleware``: Enforces 4-tier RBAC and plan quotas cleanly.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import uuid
from typing import Any

from django.conf import settings
from django.core.cache import cache
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils import translation
from django.utils.deprecation import MiddlewareMixin

from apps.core.views import REQUEST_COUNT_KEY, increment_metric

logger = logging.getLogger(__name__)

AI_ORG_QUOTA_TTL_SECONDS = 86_400  # 24-hour rolling quota window


def _supported_language_codes() -> set[str]:
    """Return lowercase language codes configured in ``settings.LANGUAGES``."""
    configured = getattr(settings, "LANGUAGES", [("en", "English")])
    return {str(code).lower() for code, _ in configured}


def resolve_language_from_request(request: HttpRequest) -> str:
    """Resolve and validate language code against ``settings.LANGUAGES``.

    Priority:
        1. ``?lang=`` query parameter (supports regional tags such as ``es-MX`` → ``es``).
        2. ``Accept-Language`` header parsed with RFC 9110 ``q=`` quality weights.
        3. Default fallback ``en``.
    """
    supported = _supported_language_codes()

    query_lang = request.GET.get("lang", "").strip().lower()
    if query_lang:
        primary = query_lang.split(";")[0].split("-")[0].split("_")[0].strip()
        return primary if primary in supported else "en"

    accept_header = request.headers.get("Accept-Language", "").strip()
    if not accept_header:
        return "en"

    candidates: list[tuple[float, int, str]] = []
    for index, raw_part in enumerate(accept_header.split(",")):
        part = raw_part.strip()
        if not part:
            continue
        segments = [seg.strip() for seg in part.split(";")]
        lang_tag = segments[0].lower()
        weight = 1.0
        for param in segments[1:]:
            if param.lower().startswith("q="):
                try:
                    weight = max(0.0, min(1.0, float(param[2:].strip())))
                except ValueError:
                    weight = 0.0
        if weight <= 0.0:
            continue
        primary = lang_tag.split("-")[0].split("_")[0]
        candidates.append((weight, -index, primary))

    candidates.sort(reverse=True)
    for _weight, _neg_idx, code in candidates:
        if code in supported:
            return code

    return "en"


def resolve_authenticated_user(request: HttpRequest) -> Any:
    """Resolve authenticated user from DRF test override, Django session, or JWT Bearer token.

    Safely bridges Django middleware execution order with stateless SimpleJWT
    tokens so ``TenantMiddleware``, ``RequestLoggingMiddleware``, and ASGI
    ``/graphql/`` views observe the authenticated user without breaking DRF's
    401 handling on missing or invalid tokens.
    """
    forced_user = getattr(request, "_force_auth_user", None)
    if forced_user is not None and getattr(forced_user, "is_authenticated", False):
        request.user = forced_user
        return forced_user

    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        from rest_framework_simplejwt.authentication import JWTAuthentication
        from rest_framework_simplejwt.exceptions import InvalidToken, TokenError

        try:
            auth_result = JWTAuthentication().authenticate(request)  # type: ignore[arg-type]
            if auth_result is not None:
                jwt_user, validated_token = auth_result
                if getattr(jwt_user, "is_authenticated", False) and getattr(
                    jwt_user, "is_active", True
                ):
                    request.user = jwt_user  # type: ignore[assignment]
                    setattr(request, "_jwt_token", validated_token)
                    return jwt_user
        except (InvalidToken, TokenError, Exception):
            # Leave request.user untouched so DRF returns 401 when appropriate.
            return None

    current_user = getattr(request, "user", None)
    if current_user is not None and getattr(current_user, "is_authenticated", False):
        return current_user

    return None


class LanguageResolutionMiddleware(MiddlewareMixin):
    """Resolve request language from query param, Accept-Language header, or default."""

    def process_request(self, request: HttpRequest) -> None:
        """Set ``request.lang`` and ``request.language`` to a validated language code."""
        resolved = resolve_language_from_request(request)
        setattr(request, "lang", resolved)
        setattr(request, "language", resolved)
        translation.activate(resolved)


class CorrelationIdMiddleware(MiddlewareMixin):
    """Propagate correlation IDs for distributed tracing."""

    def process_request(self, request: HttpRequest) -> None:
        """Attach or generate ``X-Correlation-Id`` on the request."""
        cid = request.headers.get("X-Correlation-Id", "").strip()
        if not cid or len(cid) > 128:
            cid = str(uuid.uuid4())
        setattr(request, "correlation_id", cid)

    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """Echo correlation ID back in response headers."""
        response["X-Correlation-Id"] = getattr(request, "correlation_id", str(uuid.uuid4()))
        return response


class RequestLoggingMiddleware(MiddlewareMixin):
    """Log structured JSON for all HTTP requests with correlation context."""

    _SENSITIVE_QUERY_KEYS = frozenset(
        {"token", "access_token", "refresh_token", "password", "secret", "api_key", "key"}
    )

    def process_request(self, request: HttpRequest) -> None:
        """Log incoming request with structured context."""
        correlation_id = getattr(request, "correlation_id", "unknown")
        user = resolve_authenticated_user(request)
        user_id = user.id if user is not None and getattr(user, "is_authenticated", False) else None

        log_data = {
            "type": "request",
            "correlation_id": correlation_id,
            "user_id": user_id,
            "method": request.method,
            "path": request.path,
            "query_string": self._safe_query_string(request),
            "client_ip": self._get_client_ip(request),
        }
        logger.info(json.dumps(log_data, default=str))

    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """Log outgoing response with status code and increment request metric."""
        increment_metric(REQUEST_COUNT_KEY)

        correlation_id = getattr(request, "correlation_id", "unknown")
        user = getattr(request, "user", None)
        user_id = user.id if user is not None and getattr(user, "is_authenticated", False) else None

        log_data = {
            "type": "response",
            "correlation_id": correlation_id,
            "user_id": user_id,
            "method": request.method,
            "path": request.path,
            "status_code": response.status_code,
            "client_ip": self._get_client_ip(request),
        }
        logger.info(json.dumps(log_data, default=str))
        return response

    @classmethod
    def _safe_query_string(cls, request: HttpRequest) -> str:
        """Return URL-encoded query string with sensitive parameter values redacted."""
        if not request.GET:
            return ""
        safe_params = request.GET.copy()
        for key in list(safe_params.keys()):
            if key.lower() in cls._SENSITIVE_QUERY_KEYS:
                safe_params[key] = "[REDACTED]"
        return safe_params.urlencode()

    @staticmethod
    def _get_client_ip(request: HttpRequest) -> str:
        """Extract validated client IP respecting ``settings.TRUSTED_PROXY_COUNT``."""
        trusted_proxies = int(getattr(settings, "TRUSTED_PROXY_COUNT", 0) or 0)
        if trusted_proxies > 0:
            x_forwarded_for = request.headers.get("X-Forwarded-For", "")
            if x_forwarded_for:
                hops = [hop.strip() for hop in x_forwarded_for.split(",") if hop.strip()]
                if hops:
                    index = max(0, len(hops) - trusted_proxies)
                    candidate = hops[index]
                    try:
                        return str(ipaddress.ip_address(candidate))
                    except ValueError:
                        pass

        remote_addr = str(request.META.get("REMOTE_ADDR", "") or "").strip()
        if remote_addr:
            try:
                return str(ipaddress.ip_address(remote_addr))
            except ValueError:
                return "unknown"
        return "unknown"


class ContentSecurityPolicyMiddleware(MiddlewareMixin):
    """Inject security headers on every outgoing response."""

    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """Add Content-Security-Policy, Referrer-Policy, and Permissions-Policy headers."""
        response["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "media-src 'self'; "
            "object-src 'none'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )
        response["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        return response


class TenantMiddleware(MiddlewareMixin):
    """Resolve tenant context from ``X-Organization-ID`` header or ``org`` query param.

    Attaches ``request.organization`` and ``request.membership_role``.
    """

    def process_request(self, request: HttpRequest) -> HttpResponse | None:
        """Resolve organization and membership safely for both JWT and session users."""
        setattr(request, "organization", None)
        setattr(request, "membership_role", None)

        org_id = (request.headers.get("X-Organization-ID") or request.GET.get("org") or "").strip()
        if not org_id:
            return None

        try:
            parsed_org_id = uuid.UUID(str(org_id))
        except (ValueError, TypeError):
            return JsonResponse({"error": "Invalid organization ID format"}, status=400)

        user = resolve_authenticated_user(request)
        if user is None or not getattr(user, "is_authenticated", False):
            # Defer unauthenticated rejection (401) to the view layer without DB lookup.
            return None

        from apps.core.models import Organization, OrganizationMember

        try:
            organization = Organization.objects.get(id=parsed_org_id, is_active=True)
            membership = OrganizationMember.objects.get(
                organization=organization,
                user=user,
            )
            setattr(request, "organization", organization)
            setattr(request, "membership_role", membership.role)
        except (Organization.DoesNotExist, OrganizationMember.DoesNotExist):
            return JsonResponse(
                {"error": "Organization not found or access denied"},
                status=403,
            )
        return None

    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """Pass response through unchanged."""
        return response


class TenantPermissionMiddleware(MiddlewareMixin):
    """Enforce 4-tier RBAC and plan limits on organization-scoped operations.

    Role hierarchy:
        - ``viewer``: Read-only (``GET``, ``HEAD``, ``OPTIONS``).
        - ``contributor``: May create/update tasks and invoke AI assist.
        - ``admin`` / ``owner``: Full tenant CRUD, task deletion/restoration, and AI assist.

    Plan quotas (checked only on capacity-increasing actions, avoiding delete deadlocks):
        - ``max_tasks``: Enforced on task creation and soft-delete restoration.
        - ``max_ai_requests``: Enforced on ``/api/v1/ai/`` endpoints.
    """

    MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
    WRITE_ROLES = frozenset({"contributor", "admin", "owner"})
    PRIVILEGED_ROLES = frozenset({"admin", "owner"})

    def process_view(
        self,
        request: HttpRequest,
        view_func: Any,
        view_args: tuple[Any, ...],
        view_kwargs: dict[str, Any],
    ) -> HttpResponse | None:
        """Check RBAC permissions and plan quotas for tenant-scoped requests."""
        if request.method not in self.MUTATING_METHODS:
            return None

        organization = getattr(request, "organization", None)
        if organization is None:
            return None

        role = getattr(request, "membership_role", None)
        path = request.path

        # Destructive or administrative task actions require admin or owner role
        is_privileged_action = request.method == "DELETE" or path.rstrip("/").endswith("/restore")
        required_roles = self.PRIVILEGED_ROLES if is_privileged_action else self.WRITE_ROLES

        if role not in required_roles:
            return JsonResponse({"error": "Insufficient permissions"}, status=403)

        # Enforce max_tasks ONLY when adding active tasks (create or restore)
        is_task_create = request.method == "POST" and path.rstrip("/") == "/api/v1/tasks"
        is_task_restore = request.method == "POST" and path.rstrip("/").endswith("/restore")
        if is_task_create or is_task_restore:
            active_task_count = organization.tasks.filter(is_active=True).count()
            if active_task_count >= organization.max_tasks:
                return JsonResponse({"error": "Plan limit exceeded"}, status=403)

        # Enforce max_ai_requests on AI Assist endpoints
        if request.method == "POST" and path.startswith("/api/v1/ai/"):
            quota_key = f"mltask:quota:ai:{organization.id}"
            used = int(cache.get(quota_key, 0) or 0)
            if used >= organization.max_ai_requests:
                return JsonResponse(
                    {"error": "Organization AI request limit exceeded"},
                    status=403,
                )
            try:
                cache.incr(quota_key)
            except ValueError:
                cache.set(quota_key, 1, timeout=AI_ORG_QUOTA_TTL_SECONDS)

        return None
