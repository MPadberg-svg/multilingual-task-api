"""IETF-style Redis-backed Idempotency-Key middleware for safe POST retries."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from django.core.cache import cache
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils.deprecation import MiddlewareMixin

IDEMPOTENCY_TTL_SECONDS: int = 86_400  # 24 hours
IDEMPOTENCY_LOCK_SECONDS: int = 30
MAX_IDEMPOTENCY_KEY_LENGTH: int = 128


def _principal_fingerprint(request: HttpRequest) -> str:
    """Derive caller-scoped identity digest so idempotency keys never cross users/tenants."""
    auth_header = request.headers.get("Authorization", "")
    api_key_header = request.headers.get("X-API-Key", "")
    org_header = request.headers.get("X-Organization-ID", "")
    user = getattr(request, "user", None)
    user_id = str(user.pk) if user is not None and getattr(user, "is_authenticated", False) else ""
    raw = f"{user_id}|{auth_header}|{api_key_header}|{org_header}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


def _is_valid_idempotency_key(key: str) -> bool:
    if not key or len(key) > MAX_IDEMPOTENCY_KEY_LENGTH:
        return False
    return all(32 <= ord(ch) <= 126 for ch in key)


class IdempotencyKeyMiddleware(MiddlewareMixin):
    """Deduplicate retried POST requests carrying an ``Idempotency-Key`` header.

    Guarantees:
        - Scoped per caller, path, and ``Idempotency-Key``.
        - Rejects reuse of the same ``Idempotency-Key`` with a different request
          payload with ``422 Unprocessable Entity``.
        - Blocks concurrent duplicate in-flight mutations with ``409 Conflict``.
        - Replays completed ``2xx`` JSON responses with ``X-Idempotency-Replayed: true``.
    """

    EXCLUDED_PREFIXES = ("/api/v1/auth/", "/graphql")

    def process_request(self, request: HttpRequest) -> HttpResponse | None:
        if (request.method or "").upper() != "POST":
            return None

        raw_key = request.headers.get("Idempotency-Key")
        if raw_key is None:
            return None

        cleaned_key = raw_key.strip()
        if not _is_valid_idempotency_key(cleaned_key):
            return JsonResponse(
                {
                    "error": (
                        f"Idempotency-Key must be 1–{MAX_IDEMPOTENCY_KEY_LENGTH} "
                        "printable ASCII characters."
                    )
                },
                status=400,
            )

        if any(request.path.startswith(prefix) for prefix in self.EXCLUDED_PREFIXES):
            return None

        body_hash = hashlib.sha256(request.body or b"").hexdigest()
        principal = _principal_fingerprint(request)
        key_digest = hashlib.sha256(
            f"{principal}:{request.path}:{cleaned_key}".encode("utf-8")
        ).hexdigest()[:32]

        record_key = f"mltask:idempotency:resp:{key_digest}"
        lock_key = f"mltask:idempotency:lock:{key_digest}"

        existing: dict[str, Any] | None = cache.get(record_key)
        if isinstance(existing, dict):
            if existing.get("body_hash") != body_hash:
                return JsonResponse(
                    {
                        "error": (
                            "Idempotency-Key was already used with a different request payload."
                        ),
                        "code": "idempotency_key_payload_mismatch",
                    },
                    status=422,
                )
            replayed = HttpResponse(
                content=str(existing.get("body", "")).encode("utf-8"),
                status=int(existing.get("status", 200)),
                content_type=str(existing.get("content_type", "application/json")),
            )
            replayed["X-Idempotency-Replayed"] = "true"
            return replayed

        if not cache.add(lock_key, body_hash, timeout=IDEMPOTENCY_LOCK_SECONDS):
            return JsonResponse(
                {
                    "error": "A request with this Idempotency-Key is currently in progress.",
                    "code": "idempotency_conflict",
                },
                status=409,
            )

        setattr(
            request,
            "_idempotency_meta",
            {"record_key": record_key, "lock_key": lock_key, "body_hash": body_hash},
        )
        return None

    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        meta: dict[str, str] | None = getattr(request, "_idempotency_meta", None)
        if not meta:
            return response

        try:
            content_type = response.get("Content-Type", "")
            is_streaming = getattr(response, "streaming", False)
            if (
                not is_streaming
                and 200 <= response.status_code < 300
                and "application/json" in content_type
            ):
                body_text = response.content.decode("utf-8")
                # Validate JSON serializability before storing
                json.loads(body_text)
                cache.set(
                    meta["record_key"],
                    {
                        "status": response.status_code,
                        "content_type": content_type,
                        "body": body_text,
                        "body_hash": meta["body_hash"],
                    },
                    timeout=IDEMPOTENCY_TTL_SECONDS,
                )
                response["X-Idempotency-Replayed"] = "false"
        except Exception:
            pass
        finally:
            cache.delete(meta["lock_key"])

        return response
