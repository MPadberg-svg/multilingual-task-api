"""Scoped M2M API Key authentication for automated ML annotation pipelines.

Supports ``X-API-Key: mlk_live_...`` and ``Authorization: Api-Key mlk_live_...``
headers. Raw keys are never stored; lookup uses an indexed prefix followed by a
constant-time SHA-256 digest check, role/tenant binding, and route scope checks.
"""

from __future__ import annotations

import hmac
from datetime import timedelta
from typing import Any

from django.http import HttpRequest
from django.utils import timezone

from drf_spectacular.contrib.rest_framework_simplejwt import SimpleJWTScheme
from drf_spectacular.extensions import OpenApiAuthenticationExtension
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied
from rest_framework.request import Request
from rest_framework_simplejwt.authentication import JWTAuthentication

from apps.core.models import OrganizationAPIKey
from apps.core.rls import rls_bypass

_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def extract_raw_api_key(request: HttpRequest | Request) -> str:
    """Extract raw M2M API key from ``X-API-Key`` or ``Authorization: Api-Key``."""
    direct = (request.headers.get("X-API-Key") or "").strip()
    if direct:
        return direct
    auth_header = (request.headers.get("Authorization") or "").strip()
    if auth_header.lower().startswith("api-key "):
        return auth_header[8:].strip()
    return ""


def _enforce_key_scopes(request: HttpRequest | Request, api_key: OrganizationAPIKey) -> None:
    """Enforce least-privilege route scopes for M2M API key requests."""
    path = request.path
    method = (request.method or "GET").upper()
    scopes = set(api_key.scopes or [])

    # M2M pipeline keys may never manage auth tokens, org seats, API keys, or webhooks
    if path.startswith("/api/v1/auth/logout") or (
        path.startswith("/api/v1/organizations") and method in _MUTATING_METHODS
    ):
        raise PermissionDenied("API keys cannot mutate organization or session credentials.")

    if path.startswith("/api/v1/ai/"):
        if "ai:write" not in scopes:
            raise PermissionDenied("API key missing required scope: 'ai:write'.")
        return

    if path.startswith("/api/v1/tasks/export"):
        if "tasks:export" not in scopes:
            raise PermissionDenied("API key missing required scope: 'tasks:export'.")
        return

    if path.startswith("/api/v1/tasks"):
        required = "tasks:write" if method in _MUTATING_METHODS else "tasks:read"
        if required not in scopes:
            raise PermissionDenied(f"API key missing required scope: '{required}'.")


def resolve_api_key_principal(
    request: HttpRequest | Request,
) -> tuple[Any, OrganizationAPIKey] | None:
    """Validate an API key header if present and bind tenant context on ``request``."""
    raw_key = extract_raw_api_key(request)
    if not raw_key:
        return None

    parts = raw_key.split("_")
    if len(parts) < 4 or parts[0] != "mlk" or parts[1] != "live":
        raise AuthenticationFailed("Malformed API key.")

    raw_req = getattr(request, "_request", request)
    cached_key = getattr(raw_req, "_api_key", None)
    if cached_key is not None and getattr(cached_key, "created_by", None) is not None:
        _enforce_key_scopes(request, cached_key)
        setattr(request, "organization", cached_key.organization)
        setattr(request, "membership_role", cached_key.role)
        setattr(request, "_api_key", cached_key)
        return cached_key.created_by, cached_key

    prefix = f"mlk_live_{parts[2]}"
    candidate_hash = OrganizationAPIKey.hash_raw_key(raw_key)

    with rls_bypass():
        candidates = list(
            OrganizationAPIKey.objects.select_related("organization", "created_by").filter(
                prefix=prefix,
                revoked_at__isnull=True,
            )
        )

        matched_key: OrganizationAPIKey | None = None
        for candidate in candidates:
            if hmac.compare_digest(candidate.hashed_key, candidate_hash):
                matched_key = candidate
                break

        if matched_key is None or not matched_key.is_usable:
            raise AuthenticationFailed("Invalid, expired, or revoked API key.")

        if not matched_key.organization.is_active or not matched_key.created_by.is_active:
            raise AuthenticationFailed("API key tenant or owner is inactive.")

        _enforce_key_scopes(request, matched_key)

        # Bind tenant and effective RBAC role directly onto the request
        for target_req in (raw_req, request):
            setattr(target_req, "organization", matched_key.organization)
            setattr(target_req, "membership_role", matched_key.role)
            setattr(target_req, "_api_key", matched_key)

        now = timezone.now()
        if matched_key.last_used_at is None or (now - matched_key.last_used_at) > timedelta(
            seconds=60
        ):
            OrganizationAPIKey.objects.filter(id=matched_key.id).update(last_used_at=now)
            matched_key.last_used_at = now

    return matched_key.created_by, matched_key


class OrganizationAPIKeyAuthentication(BaseAuthentication):
    """DRF authentication backend for ``OrganizationAPIKey`` credentials."""

    def authenticate(self, request: Request) -> tuple[Any, OrganizationAPIKey] | None:
        return resolve_api_key_principal(request)

    def authenticate_header(self, request: Request) -> str:
        return "Api-Key"


class OrganizationAPIKeyScheme(OpenApiAuthenticationExtension):  # type: ignore[no-untyped-call]
    """Register ``X-API-Key`` security scheme in OpenAPI 3.0 / Swagger UI."""

    target_class = "apps.core.authentication.OrganizationAPIKeyAuthentication"
    name = "OrganizationApiKeyAuth"

    def get_security_definition(self, auto_schema: Any) -> dict[str, Any]:
        return {
            "type": "apiKey",
            "in": "header",
            "name": "X-API-Key",
            "description": "Scoped organization M2M API key (mlk_live_<prefix>_<secret>).",
        }


class CachedJWTAuthentication(JWTAuthentication):
    """JWT authentication backend that reuses user/token resolved earlier in middleware."""

    def authenticate(self, request: Request) -> tuple[Any, Any] | None:
        raw_req = getattr(request, "_request", request)
        cached_user = getattr(raw_req, "_resolved_jwt_user", None)
        cached_token = getattr(raw_req, "_jwt_token", None)
        if cached_user is not None and cached_token is not None:
            return cached_user, cached_token
        result = super().authenticate(request)
        if result is not None:
            user_obj, validated_token = result
            setattr(raw_req, "_resolved_jwt_user", user_obj)
            setattr(raw_req, "_jwt_token", validated_token)
        return result


class CachedJWTScheme(SimpleJWTScheme):  # type: ignore[no-untyped-call]
    """Preserve SimpleJWT ``jwtAuth`` OpenAPI 3.0 security definition for ``CachedJWTAuthentication``."""

    target_class = "apps.core.authentication.CachedJWTAuthentication"
