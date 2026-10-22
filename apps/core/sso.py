"""Enterprise OIDC ID-token exchange and RFC 7643/7644 SCIM 2.0 lifecycle provisioning.

Security properties:
    - OIDC ID tokens strictly require asymmetric ``RS256`` or ``ES256`` signatures verified
      against the organization's pinned JWKS or PEM public key (``alg=none`` and symmetric
      ``HS256`` key-confusion payloads are rejected prior to decoding).
    - External IdP group/role claims map onto ``viewer``, ``contributor`` (including RLHF
      ``annotator`` / ``reviewer`` aliases), or ``admin`` — never auto-escalating to ``owner``.
    - SCIM 2.0 bearer credentials (``scim_live_<id>_<secret>``) are stored exclusively as
      SHA-256 digests and verified in constant time scoped to the target organization.
    - Deprovisioning a user in Organization A preserves their account if they hold active
      memberships in other tenants, while disabling ``user.is_active`` when no tenant
      memberships remain.
"""

from __future__ import annotations

import hmac
import re
from typing import Any

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from django.utils import timezone

import jwt
from jwt import InvalidTokenError, PyJWK
from rest_framework.request import Request
from rest_framework_simplejwt.tokens import RefreshToken

from apps.core.models import (
    AuditLog,
    Organization,
    OrganizationAPIKey,
    OrganizationMember,
    OrganizationSSOConfig,
)
from apps.core.outbox import enqueue_outbox_event
from apps.core.rls import rls_bypass
from apps.core.security import InputValidator

User = get_user_model()

SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCIM_PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"

_ALLOWED_OIDC_ALGS: frozenset[str] = frozenset({"RS256", "ES256"})
_ROLE_ALIASES: dict[str, str] = {
    "viewer": "viewer",
    "contributor": "contributor",
    "annotator": "contributor",
    "reviewer": "contributor",
    "admin": "admin",
}
_ASSIGNABLE_ROLE_RANK: dict[str, int] = {
    "viewer": 1,
    "contributor": 2,
    "admin": 3,
}
_SCIM_EQ_FILTER_RE = re.compile(
    r'^\s*(userName|externalId)\s+eq\s+"([^"\\]{1,254})"\s*$',
    re.IGNORECASE,
)


class SSOAuthenticationError(Exception):
    """Raised when OIDC SSO token validation or tenant policy checks fail."""

    def __init__(self, message: str, *, status_code: int = 401) -> None:
        super().__init__(message)
        self.status_code = status_code


class SCIMProvisioningError(Exception):
    """Raised on RFC 7644 SCIM 2.0 authentication, validation, or quota errors."""

    def __init__(
        self,
        detail: str,
        *,
        status_code: int = 400,
        scim_type: str | None = None,
    ) -> None:
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code
        self.scim_type = scim_type

    def as_scim_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schemas": [SCIM_ERROR_SCHEMA],
            "detail": self.detail,
            "status": str(self.status_code),
        }
        if self.scim_type:
            payload["scimType"] = self.scim_type
        return payload


def normalize_assignable_role(raw_role: str | None, fallback: str = "viewer") -> str:
    """Normalize an IdP/SCIM role name into an assignable non-owner RBAC role."""
    cleaned = (raw_role or "").strip().lower()
    if cleaned in _ROLE_ALIASES:
        return _ROLE_ALIASES[cleaned]
    return _ROLE_ALIASES.get(fallback.strip().lower(), "viewer")


def resolve_mapped_role(
    sso_config: OrganizationSSOConfig,
    raw_groups_or_roles: Any,
) -> str:
    """Map external IdP group/role claims to the highest permitted ``OrganizationMember`` role."""
    default_role = normalize_assignable_role(sso_config.default_role, fallback="viewer")
    mapping = sso_config.role_mapping if isinstance(sso_config.role_mapping, dict) else {}
    if not raw_groups_or_roles or not mapping:
        return default_role

    if isinstance(raw_groups_or_roles, str):
        candidates = [raw_groups_or_roles]
    elif isinstance(raw_groups_or_roles, list):
        candidates = [str(item) for item in raw_groups_or_roles if isinstance(item, (str, int))]
    else:
        return default_role

    normalized_map = {
        str(k).strip().lower(): normalize_assignable_role(str(v), fallback=default_role)
        for k, v in mapping.items()
    }
    best_role = default_role
    for group_name in candidates:
        mapped = normalized_map.get(group_name.strip().lower())
        if mapped and _ASSIGNABLE_ROLE_RANK[mapped] > _ASSIGNABLE_ROLE_RANK[best_role]:
            best_role = mapped
    return best_role


def _enforce_allowed_domain(sso_config: OrganizationSSOConfig, email: str) -> None:
    allowed = sso_config.allowed_domains if isinstance(sso_config.allowed_domains, list) else []
    normalized_domains = {str(d).strip().lower().lstrip("@") for d in allowed if str(d).strip()}
    if not normalized_domains:
        return
    parts = email.rsplit("@", 1)
    domain = parts[1].lower() if len(parts) == 2 else ""
    if domain not in normalized_domains:
        raise SSOAuthenticationError(
            f"Email domain '{domain}' is not permitted for this organization's SSO policy.",
            status_code=403,
        )


def _resolve_verification_key(
    sso_config: OrganizationSSOConfig,
    header: dict[str, Any],
) -> Any:
    jwks = sso_config.jwks_json if isinstance(sso_config.jwks_json, dict) else {}
    keys_list = jwks.get("keys")
    kid = header.get("kid")

    if isinstance(keys_list, list) and keys_list:
        selected_jwk: dict[str, Any] | None = None
        if kid:
            for item in keys_list:
                if isinstance(item, dict) and item.get("kid") == kid:
                    selected_jwk = item
                    break
            if selected_jwk is None:
                raise SSOAuthenticationError("OIDC token kid does not match any configured JWK.")
        elif len(keys_list) == 1 and isinstance(keys_list[0], dict):
            selected_jwk = keys_list[0]
        else:
            raise SSOAuthenticationError("OIDC token header missing kid for multi-key JWKS.")

        try:
            return PyJWK.from_dict(selected_jwk).key
        except Exception as exc:
            raise SSOAuthenticationError("Configured JWKS key material is invalid.") from exc

    pem = (sso_config.public_key_pem or "").strip()
    if pem:
        return pem

    raise SSOAuthenticationError(
        "Organization SSO has no JWKS or PEM verification key configured.",
        status_code=503,
    )


def verify_oidc_id_token(
    sso_config: OrganizationSSOConfig,
    raw_id_token: str,
) -> dict[str, Any]:
    """Cryptographically verify an OIDC ``id_token`` against ``sso_config``."""
    if not sso_config.oidc_issuer or not sso_config.oidc_client_id:
        raise SSOAuthenticationError(
            "Organization OIDC issuer or client_id is not configured.",
            status_code=503,
        )

    try:
        header = jwt.get_unverified_header(raw_id_token)
    except InvalidTokenError as exc:
        raise SSOAuthenticationError("Malformed OIDC ID token header.") from exc

    alg = str(header.get("alg", "")).upper()
    if alg not in _ALLOWED_OIDC_ALGS:
        raise SSOAuthenticationError(
            f"Unsupported OIDC signing algorithm '{alg}'. Required: RS256 or ES256."
        )

    verification_key = _resolve_verification_key(sso_config, header)
    try:
        claims: dict[str, Any] = jwt.decode(
            raw_id_token,
            verification_key,
            algorithms=[alg],
            audience=sso_config.oidc_client_id,
            issuer=sso_config.oidc_issuer,
            options={"require": ["exp", "iat", "sub", "iss", "aud"]},
        )
    except InvalidTokenError as exc:
        raise SSOAuthenticationError(f"OIDC token verification failed: {exc}") from exc

    email = str(claims.get("email") or "").strip().lower()
    if not email or "@" not in email:
        raise SSOAuthenticationError("OIDC ID token missing valid 'email' claim.")

    if claims.get("email_verified") is False:
        raise SSOAuthenticationError("OIDC identity email is not verified by the provider.")

    _enforce_allowed_domain(sso_config, email)
    return claims


def _sanitize_name_part(raw: Any) -> str:
    if not isinstance(raw, str) or not raw.strip():
        return ""
    is_bad, _ = InputValidator.detect_injection(raw)
    if is_bad:
        return ""
    try:
        return InputValidator.sanitize_string(raw, max_length=150)
    except ValueError:
        return ""


def exchange_oidc_token_for_jwt(
    *,
    organization_slug: str,
    raw_id_token: str,
    ip_address: str | None = None,
    user_agent: str = "",
) -> dict[str, Any]:
    """Validate an external OIDC ``id_token``, JIT-provision/sync membership, and mint SimpleJWT."""
    slug = organization_slug.strip().lower()
    with rls_bypass():
        org = Organization.objects.filter(slug=slug, is_active=True).first()
        if org is None:
            raise SSOAuthenticationError("Organization not found or inactive.", status_code=404)

        sso_config = OrganizationSSOConfig.objects.filter(organization=org, enabled=True).first()
        if sso_config is None:
            raise SSOAuthenticationError(
                "OIDC SSO is not enabled for this organization.",
                status_code=403,
            )

        claims = verify_oidc_id_token(sso_config, raw_id_token)
        email = str(claims["email"]).strip().lower()
        sub = str(claims["sub"]).strip()
        given_name = _sanitize_name_part(claims.get("given_name"))
        family_name = _sanitize_name_part(claims.get("family_name"))
        mapped_role = resolve_mapped_role(sso_config, claims.get(sso_config.role_claim or "groups"))

        with transaction.atomic():
            user = User.objects.filter(email__iexact=email).first()
            if user is None:
                if not sso_config.jit_provisioning:
                    raise SSOAuthenticationError(
                        "Just-in-time provisioning is disabled for this organization.",
                        status_code=403,
                    )
                user = User(
                    email=User.objects.normalize_email(email),
                    first_name=given_name,
                    last_name=family_name,
                    is_active=True,
                )
                user.set_unusable_password()
                user.save()
            else:
                if not user.is_active:
                    raise SSOAuthenticationError("User account is deactivated.", status_code=403)
                updated_fields: list[str] = []
                if given_name and user.first_name != given_name:
                    user.first_name = given_name
                    updated_fields.append("first_name")
                if family_name and user.last_name != family_name:
                    user.last_name = family_name
                    updated_fields.append("last_name")
                if updated_fields:
                    user.save(update_fields=updated_fields)

            membership = OrganizationMember.objects.filter(organization=org, user=user).first()
            if membership is None:
                if not sso_config.jit_provisioning:
                    raise SSOAuthenticationError(
                        "User is not a provisioned member of this organization.",
                        status_code=403,
                    )
                try:
                    membership = OrganizationMember.objects.create(
                        organization=org,
                        user=user,
                        role=mapped_role,
                    )
                except DjangoValidationError as exc:
                    raise SSOAuthenticationError(
                        "Organization user seat limit exceeded.",
                        status_code=403,
                    ) from exc
            elif membership.role != "owner" and membership.role != mapped_role:
                membership.role = mapped_role
                membership.save(update_fields=["role"])

            AuditLog.objects.create(
                organization=org,
                user=user,
                action="sso_login",
                resource_type="OrganizationSSOConfig",
                resource_id=str(sso_config.id),
                ip_address=ip_address,
                user_agent=user_agent[:500],
                metadata={
                    "sub": sub,
                    "issuer": sso_config.oidc_issuer,
                    "role": membership.role,
                },
            )

        refresh = RefreshToken.for_user(user)
        return {
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "organization_id": str(org.id),
            "organization_slug": org.slug,
            "role": membership.role,
            "user": {
                "id": str(user.id),
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
            },
        }


def authenticate_scim_bearer(
    request: Request,
    org_id: str,
) -> tuple[Organization, OrganizationSSOConfig]:
    """Authenticate an incoming RFC 7644 SCIM 2.0 request via ``Bearer scim_live_...``."""
    auth_header = (request.headers.get("Authorization") or "").strip()
    if not auth_header.lower().startswith("bearer "):
        raise SCIMProvisioningError(
            "Missing SCIM Bearer credential.",
            status_code=401,
        )

    raw_credential = auth_header[7:].strip()
    parts = raw_credential.split("_")
    if len(parts) < 4 or parts[0] != "scim" or parts[1] != "live":
        raise SCIMProvisioningError(
            "Malformed SCIM Bearer credential.",
            status_code=401,
        )

    expected_prefix = f"scim_live_{parts[2]}"
    candidate_digest = OrganizationSSOConfig.hash_scim_token(raw_credential)

    with rls_bypass():
        org = Organization.objects.filter(id=org_id, is_active=True).first()
        if org is None:
            raise SCIMProvisioningError("Organization not found.", status_code=404)

        sso_config = OrganizationSSOConfig.objects.filter(
            organization=org,
            scim_enabled=True,
        ).first()
        if (
            sso_config is None
            or not sso_config.scim_token_hash
            or sso_config.scim_token_prefix != expected_prefix
            or not hmac.compare_digest(sso_config.scim_token_hash, candidate_digest)
        ):
            raise SCIMProvisioningError(
                "Invalid or disabled SCIM Bearer credential for this organization.",
                status_code=401,
            )

    return org, sso_config


def serialize_scim_member(member: OrganizationMember) -> dict[str, Any]:
    """Serialize an ``OrganizationMember`` as an RFC 7643 ``User`` resource."""
    user = member.user
    return {
        "schemas": [SCIM_USER_SCHEMA],
        "id": str(member.id),
        "externalId": member.scim_external_id or str(user.id),
        "userName": user.email,
        "name": {
            "givenName": user.first_name,
            "familyName": user.last_name,
            "formatted": user.get_full_name(),
        },
        "emails": [
            {
                "value": user.email,
                "type": "work",
                "primary": True,
            }
        ],
        "active": bool(user.is_active),
        "roles": [{"value": member.role, "primary": True}],
        "meta": {
            "resourceType": "User",
            "created": member.joined_at.isoformat(),
            "location": f"/api/v1/organizations/{member.organization_id}/scim/v2/Users/{member.id}",
        },
    }


def _extract_scim_email(payload: dict[str, Any]) -> str:
    raw_username = str(payload.get("userName") or "").strip().lower()
    if raw_username and "@" in raw_username:
        return raw_username
    emails = payload.get("emails")
    if isinstance(emails, list):
        for item in emails:
            if isinstance(item, dict):
                val = str(item.get("value") or "").strip().lower()
                if val and "@" in val:
                    return val
    raise SCIMProvisioningError(
        "SCIM User payload must supply a valid email in 'userName' or 'emails'.",
        status_code=400,
        scim_type="invalidValue",
    )


def _extract_scim_role(payload: dict[str, Any], sso_config: OrganizationSSOConfig) -> str:
    roles = payload.get("roles")
    raw_values: list[str] = []
    if isinstance(roles, list):
        for item in roles:
            if isinstance(item, dict) and item.get("value"):
                raw_values.append(str(item["value"]))
            elif isinstance(item, str):
                raw_values.append(item)

    if not raw_values:
        return normalize_assignable_role(sso_config.default_role, fallback="viewer")

    # Apply organization role_mapping first if present, otherwise direct role/alias match
    if sso_config.role_mapping:
        mapped = resolve_mapped_role(sso_config, raw_values)
        if mapped != normalize_assignable_role(sso_config.default_role):
            return mapped

    best = normalize_assignable_role(raw_values[0], fallback=sso_config.default_role)
    for raw in raw_values[1:]:
        candidate = normalize_assignable_role(raw, fallback=sso_config.default_role)
        if _ASSIGNABLE_ROLE_RANK[candidate] > _ASSIGNABLE_ROLE_RANK[best]:
            best = candidate
    return best


def scim_list_users(
    *,
    org: Organization,
    filter_expr: str = "",
    start_index: int = 1,
    count: int = 100,
) -> dict[str, Any]:
    """List organization members in RFC 7644 ``ListResponse`` format with optional ``eq`` filter."""
    safe_start = max(1, int(start_index))
    safe_count = max(1, min(200, int(count)))

    with rls_bypass():
        qs = OrganizationMember.objects.filter(organization=org).select_related("user")
        cleaned_filter = filter_expr.strip()
        if cleaned_filter:
            match = _SCIM_EQ_FILTER_RE.match(cleaned_filter)
            if not match:
                raise SCIMProvisioningError(
                    "Unsupported SCIM filter expression; expected 'userName eq \"...\"' or 'externalId eq \"...\"'.",
                    status_code=400,
                    scim_type="invalidFilter",
                )
            attr, target_val = match.group(1).lower(), match.group(2)
            if attr == "username":
                qs = qs.filter(user__email__iexact=target_val)
            else:
                qs = qs.filter(scim_external_id=target_val)

        ordered = qs.order_by("joined_at", "id")
        total = ordered.count()
        offset = safe_start - 1
        members = list(ordered[offset : offset + safe_count])

    return {
        "schemas": [SCIM_LIST_SCHEMA],
        "totalResults": total,
        "startIndex": safe_start,
        "itemsPerPage": len(members),
        "Resources": [serialize_scim_member(m) for m in members],
    }


def scim_provision_user(
    *,
    org: Organization,
    sso_config: OrganizationSSOConfig,
    payload: dict[str, Any],
    ip_address: str | None = None,
    user_agent: str = "",
) -> tuple[dict[str, Any], bool]:
    """Provision or synchronize a user and ``OrganizationMember`` via SCIM 2.0 ``POST /Users``."""
    email = _extract_scim_email(payload)
    try:
        _enforce_allowed_domain(sso_config, email)
    except SSOAuthenticationError as exc:
        raise SCIMProvisioningError(
            str(exc),
            status_code=403,
            scim_type="invalidValue",
        ) from exc

    raw_name = payload.get("name")
    name_obj = raw_name if isinstance(raw_name, dict) else {}
    given_name = _sanitize_name_part(name_obj.get("givenName"))
    family_name = _sanitize_name_part(name_obj.get("familyName"))
    external_id = str(payload.get("externalId") or "").strip()[:255]
    is_active = bool(payload.get("active", True))
    target_role = _extract_scim_role(payload, sso_config)

    with rls_bypass():
        with transaction.atomic():
            user = User.objects.filter(email__iexact=email).first()
            if user is None:
                user = User(
                    email=User.objects.normalize_email(email),
                    first_name=given_name,
                    last_name=family_name,
                    is_active=is_active,
                )
                user.set_unusable_password()
                user.save()
            else:
                updates: list[str] = []
                if given_name and user.first_name != given_name:
                    user.first_name = given_name
                    updates.append("first_name")
                if family_name and user.last_name != family_name:
                    user.last_name = family_name
                    updates.append("last_name")
                if is_active and not user.is_active:
                    user.is_active = True
                    updates.append("is_active")
                if updates:
                    user.save(update_fields=updates)

            member = (
                OrganizationMember.objects.select_related("user")
                .filter(organization=org, user=user)
                .first()
            )
            created = False
            if member is None:
                try:
                    member = OrganizationMember.objects.create(
                        organization=org,
                        user=user,
                        role=target_role,
                        scim_external_id=external_id,
                        provisioned_by_scim=True,
                    )
                    created = True
                except DjangoValidationError as exc:
                    raise SCIMProvisioningError(
                        "Organization user seat limit exceeded.",
                        status_code=409,
                        scim_type="tooMany",
                    ) from exc
            else:
                member_updates: list[str] = ["provisioned_by_scim"]
                member.provisioned_by_scim = True
                if external_id and member.scim_external_id != external_id:
                    member.scim_external_id = external_id
                    member_updates.append("scim_external_id")
                if member.role != "owner" and member.role != target_role:
                    member.role = target_role
                    member_updates.append("role")
                member.save(update_fields=member_updates)

            enqueue_outbox_event(
                organization_id=str(org.id),
                event_type="scim.user_provisioned",
                payload={
                    "member_id": str(member.id),
                    "user_id": str(user.id),
                    "email": user.email,
                    "role": member.role,
                    "external_id": member.scim_external_id,
                },
            )
            AuditLog.objects.create(
                organization=org,
                user=user,
                action="scim_user_provisioned",
                resource_type="OrganizationMember",
                resource_id=str(member.id),
                ip_address=ip_address,
                user_agent=user_agent[:500],
                metadata={
                    "email": user.email,
                    "role": member.role,
                    "external_id": member.scim_external_id,
                    "created": created,
                },
            )
            return serialize_scim_member(member), created


def _deprovision_member_locked(
    *,
    org: Organization,
    member: OrganizationMember,
    ip_address: str | None,
    user_agent: str,
) -> dict[str, Any]:
    """Remove tenant membership, revoke tenant API keys, and deactivate orphan single-org users."""
    if member.role == "owner":
        owner_count = OrganizationMember.objects.filter(organization=org, role="owner").count()
        if owner_count <= 1:
            raise SCIMProvisioningError(
                "Cannot deprovision the last owner of an organization.",
                status_code=400,
                scim_type="mutability",
            )

    user = member.user
    member_id_str = str(member.id)
    ext_id = member.scim_external_id or str(user.id)
    joined_iso = member.joined_at.isoformat()
    role_snapshot = member.role

    now = timezone.now()
    OrganizationAPIKey.objects.filter(
        organization=org,
        created_by=user,
        revoked_at__isnull=True,
    ).update(revoked_at=now)

    member.delete()

    remaining_memberships = OrganizationMember.objects.filter(
        user=user,
        organization__is_active=True,
    ).count()
    if remaining_memberships == 0 and user.is_active:
        user.is_active = False
        user.save(update_fields=["is_active"])

    enqueue_outbox_event(
        organization_id=str(org.id),
        event_type="scim.user_deprovisioned",
        payload={
            "member_id": member_id_str,
            "user_id": str(user.id),
            "email": user.email,
            "external_id": ext_id,
        },
    )
    AuditLog.objects.create(
        organization=org,
        user=user,
        action="scim_user_deprovisioned",
        resource_type="OrganizationMember",
        resource_id=member_id_str,
        ip_address=ip_address,
        user_agent=user_agent[:500],
        metadata={"email": user.email, "external_id": ext_id},
    )

    return {
        "schemas": [SCIM_USER_SCHEMA],
        "id": member_id_str,
        "externalId": ext_id,
        "userName": user.email,
        "name": {
            "givenName": user.first_name,
            "familyName": user.last_name,
            "formatted": user.get_full_name(),
        },
        "emails": [{"value": user.email, "type": "work", "primary": True}],
        "active": False,
        "roles": [{"value": role_snapshot, "primary": True}],
        "meta": {
            "resourceType": "User",
            "created": joined_iso,
            "location": f"/api/v1/organizations/{org.id}/scim/v2/Users/{member_id_str}",
        },
    }


def scim_get_user(*, org: Organization, member_id: str) -> dict[str, Any]:
    """Retrieve a single SCIM 2.0 ``User`` resource."""
    with rls_bypass():
        member = (
            OrganizationMember.objects.select_related("user")
            .filter(id=member_id, organization=org)
            .first()
        )
    if member is None:
        raise SCIMProvisioningError("SCIM User not found.", status_code=404)
    return serialize_scim_member(member)


def scim_update_user(
    *,
    org: Organization,
    sso_config: OrganizationSSOConfig,
    member_id: str,
    payload: dict[str, Any],
    is_patch: bool,
    ip_address: str | None = None,
    user_agent: str = "",
) -> dict[str, Any]:
    """Handle SCIM 2.0 ``PATCH`` (``PatchOp``) and ``PUT`` updates including ``active=false`` offboarding."""
    with rls_bypass():
        with transaction.atomic():
            member = (
                OrganizationMember.objects.select_related("user")
                .filter(id=member_id, organization=org)
                .first()
            )
            if member is None:
                raise SCIMProvisioningError("SCIM User not found.", status_code=404)

            active_flag: bool | None = None
            new_role: str | None = None
            given_name: str | None = None
            family_name: str | None = None
            external_id: str | None = None

            if is_patch:
                ops = payload.get("Operations")
                if not isinstance(ops, list) or not ops:
                    raise SCIMProvisioningError(
                        "SCIM PatchOp requires a non-empty 'Operations' list.",
                        status_code=400,
                        scim_type="invalidSyntax",
                    )
                for op_item in ops:
                    if not isinstance(op_item, dict):
                        continue
                    op_name = str(op_item.get("op") or "replace").strip().lower()
                    if op_name not in {"replace", "add"}:
                        continue
                    path = str(op_item.get("path") or "").strip().lower()
                    val = op_item.get("value")

                    if path == "active" and isinstance(val, bool):
                        active_flag = val
                    elif path == "externalid" and isinstance(val, str):
                        external_id = val.strip()[:255]
                    elif path == "name.givenname" and isinstance(val, str):
                        given_name = _sanitize_name_part(val)
                    elif path == "name.familyname" and isinstance(val, str):
                        family_name = _sanitize_name_part(val)
                    elif path == "roles":
                        new_role = _extract_scim_role({"roles": val}, sso_config)
                    elif not path and isinstance(val, dict):
                        if isinstance(val.get("active"), bool):
                            active_flag = val["active"]
                        if isinstance(val.get("externalId"), str):
                            external_id = str(val["externalId"]).strip()[:255]
                        if "roles" in val:
                            new_role = _extract_scim_role({"roles": val["roles"]}, sso_config)
                        if isinstance(val.get("name"), dict):
                            if "givenName" in val["name"]:
                                given_name = _sanitize_name_part(val["name"].get("givenName"))
                            if "familyName" in val["name"]:
                                family_name = _sanitize_name_part(val["name"].get("familyName"))
            else:
                if "active" in payload and isinstance(payload["active"], bool):
                    active_flag = payload["active"]
                if "externalId" in payload:
                    external_id = str(payload.get("externalId") or "").strip()[:255]
                if "roles" in payload:
                    new_role = _extract_scim_role(payload, sso_config)
                raw_name = payload.get("name")
                if isinstance(raw_name, dict):
                    given_name = _sanitize_name_part(raw_name.get("givenName"))
                    family_name = _sanitize_name_part(raw_name.get("familyName"))

            if active_flag is False:
                return _deprovision_member_locked(
                    org=org,
                    member=member,
                    ip_address=ip_address,
                    user_agent=user_agent,
                )

            user = member.user
            user_updates: list[str] = []
            if active_flag is True and not user.is_active:
                user.is_active = True
                user_updates.append("is_active")
            if given_name is not None and user.first_name != given_name:
                user.first_name = given_name
                user_updates.append("first_name")
            if family_name is not None and user.last_name != family_name:
                user.last_name = family_name
                user_updates.append("last_name")
            if user_updates:
                user.save(update_fields=user_updates)

            member_updates: list[str] = []
            if external_id is not None and member.scim_external_id != external_id:
                member.scim_external_id = external_id
                member_updates.append("scim_external_id")
            if new_role is not None and member.role != "owner" and member.role != new_role:
                member.role = new_role
                member_updates.append("role")
            if member_updates:
                member.save(update_fields=member_updates)

            AuditLog.objects.create(
                organization=org,
                user=user,
                action="scim_user_updated",
                resource_type="OrganizationMember",
                resource_id=str(member.id),
                ip_address=ip_address,
                user_agent=user_agent[:500],
                metadata={"role": member.role, "external_id": member.scim_external_id},
            )
            return serialize_scim_member(member)


def scim_delete_user(
    *,
    org: Organization,
    member_id: str,
    ip_address: str | None = None,
    user_agent: str = "",
) -> None:
    """Deprovision an organization member via SCIM 2.0 ``DELETE /Users/<id>``."""
    with rls_bypass():
        with transaction.atomic():
            member = (
                OrganizationMember.objects.select_related("user")
                .filter(id=member_id, organization=org)
                .first()
            )
            if member is None:
                raise SCIMProvisioningError("SCIM User not found.", status_code=404)
            _deprovision_member_locked(
                org=org,
                member=member,
                ip_address=ip_address,
                user_agent=user_agent,
            )
