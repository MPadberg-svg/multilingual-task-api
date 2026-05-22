"""Core middleware for language resolution, correlation IDs, security, and tenancy.

Provides:
    - ``LanguageResolutionMiddleware``: Extracts ``?lang=`` → ``Accept-Language`` → ``en``.
    - ``CorrelationIdMiddleware``: Attaches ``X-Correlation-Id`` to requests/responses.
    - ``ContentSecurityPolicyMiddleware``: Injects security headers on every response.
    - ``TenantMiddleware``: Resolves organization and membership role from headers/params.
    - ``TenantPermissionMiddleware``: Enforces plan limits and RBAC on mutating operations.
"""

import json
import logging
import uuid

from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger(__name__)


class LanguageResolutionMiddleware(MiddlewareMixin):
    """Resolve request language from query param, header, or default."""

    def process_request(self, request: HttpRequest) -> None:
        """Set ``request.lang`` and ``request.language`` based on priority chain.

        Priority:
            1. Query param ``?lang=``
            2. ``Accept-Language`` header
            3. Fallback ``en``
        """
        lang = request.GET.get("lang")
        if not lang:
            lang = request.headers.get("Accept-Language", "en").split(",")[0].strip()
        if not lang or len(lang) > 10:
            lang = "en"
        request.lang = lang.lower()
        request.language = lang.lower()  # FIXED: also set request.language for serializer/views


class CorrelationIdMiddleware(MiddlewareMixin):
    """Propagate correlation IDs for distributed tracing."""

    def process_request(self, request: HttpRequest) -> None:
        """Attach or generate ``X-Correlation-Id`` on the request."""
        cid = request.headers.get("X-Correlation-Id")
        if not cid:
            cid = str(uuid.uuid4())
        request.correlation_id = cid

    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """Echo correlation ID back in response headers."""
        response["X-Correlation-Id"] = getattr(request, "correlation_id", str(uuid.uuid4()))
        return response


class RequestLoggingMiddleware(MiddlewareMixin):
    """Log structured JSON for all HTTP requests with correlation context."""

    def process_request(self, request: HttpRequest) -> None:
        """Log incoming request with structured context.

        Logs correlation ID, authenticated user, method, path, and query string.
        """
        correlation_id = getattr(request, "correlation_id", "unknown")
        user = getattr(request, "user", None)
        user_id = user.id if user and user.is_authenticated else None

        log_data = {
            "type": "request",
            "correlation_id": correlation_id,
            "user_id": user_id,
            "method": request.method,
            "path": request.path,
            "query_string": request.GET.urlencode(),
            "client_ip": self._get_client_ip(request),
        }
        logger.info(json.dumps(log_data, default=str))

    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """Log outgoing response with status code and correlation context."""
        correlation_id = getattr(request, "correlation_id", "unknown")
        user = getattr(request, "user", None)
        user_id = user.id if user and user.is_authenticated else None

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

    @staticmethod
    def _get_client_ip(request: HttpRequest) -> str:
        """Extract client IP from X-Forwarded-For or REMOTE_ADDR."""
        x_forwarded_for = request.headers.get("X-Forwarded-For")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR", "unknown")


class ContentSecurityPolicyMiddleware(MiddlewareMixin):
    """Inject security headers on every outgoing response.

    Headers added:
        - ``Content-Security-Policy``
        - ``Referrer-Policy``
        - ``Permissions-Policy``
    """

    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """Add security headers to the response.

        Args:
            request: Current HTTP request.
            response: Outgoing HTTP response.

        Returns:
            Response with security headers attached.
        """
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

    def process_request(self, request: HttpRequest) -> None:
        """Resolve organization and membership from request.

        Looks up ``Organization`` and ``OrganizationMember`` by UUID.
        Falls back to ``None`` on any validation or lookup failure.
        """
        org_id = request.headers.get("X-Organization-ID") or request.GET.get("org")
        if not org_id:
            request.organization = None
            request.membership_role = None
            return

        try:
            uuid.UUID(str(org_id))
        except (ValueError, TypeError):
            request.organization = None
            request.membership_role = None
            return

        from apps.core.models import Organization, OrganizationMember

        try:
            organization = Organization.objects.get(id=org_id, is_active=True)
            membership = OrganizationMember.objects.get(
                organization=organization,
                user=request.user,
            )
            request.organization = organization
            request.membership_role = membership.role
        except (Organization.DoesNotExist, OrganizationMember.DoesNotExist):
            request.organization = None
            request.membership_role = None

    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """Pass response through unchanged."""
        return response


class TenantPermissionMiddleware(MiddlewareMixin):
    """Enforce plan limits and RBAC on mutating HTTP methods.

    Blocks ``POST``, ``PUT``, ``PATCH``, ``DELETE`` if:
        - No organization is resolved.
        - User role is not ``admin`` or ``owner``.
        - Organization task count exceeds ``max_tasks`` plan limit.
    """

    MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
    ADMIN_ROLES = {"admin", "owner"}

    def process_view(self, request: HttpRequest, view_func, view_args, view_kwargs):
        """Check permissions and plan limits for mutating operations.

        Args:
            request: Current HTTP request.
            view_func: Resolved view callable.
            view_args: Positional view arguments.
            view_kwargs: Keyword view arguments.

        Returns:
            ``JsonResponse`` with 403 if checks fail, otherwise ``None``.
        """
        if request.method not in self.MUTATING_METHODS:
            return None

        organization = getattr(request, "organization", None)
        if organization is None:
            return None

        role = getattr(request, "membership_role", None)
        if role not in self.ADMIN_ROLES:
            return JsonResponse(
                {"error": "Insufficient permissions"},
                status=403,
            )

        task_count = organization.tasks.filter(is_active=True).count()
        if task_count >= organization.max_tasks:
            return JsonResponse(
                {"error": "Plan limit exceeded"},
                status=403,
            )

        return None