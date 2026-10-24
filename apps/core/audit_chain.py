"""Cryptographic SHA-256 hash-chaining, Ed25519/KMS transparency & S3 WORM checkpointing.

Each ``AuditLog`` row is sealed at insert time with:
    - ``chain_seq``: strictly monotonic 1-based sequence number within its tenant chain
      (or the ``global`` chain when ``organization_id`` is ``NULL``).
    - ``prev_hash``: ``entry_hash`` of row ``chain_seq - 1`` (``"0" * 64`` at genesis).
    - ``entry_hash``: deterministic SHA-256 hex digest over canonical JSON of all
      security-relevant columns plus ``(chain_seq, prev_hash)``.

``AuditChainCheckpoint`` rows notarize periodic snapshots of each tenant's hash chain with
a domain-separated HMAC-SHA256 MAC, optional asymmetric public-key transparency signatures
(``Ed25519`` or AWS KMS ``ECDSA_SHA_256`` via zero-dependency AWS Signature Version 4 HTTPS
``POST``), and optional Amazon S3 Object Lock (``COMPLIANCE`` mode) WORM archival, enabling
third-party auditors to verify WORM archives offline with a public key alone.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import logging
import os
import ssl
from collections.abc import Callable
from datetime import datetime, timedelta
from datetime import timezone as dt_timezone
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import connections, transaction
from django.utils import timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from apps.core.db_router import use_read_replica
from apps.core.rls import rls_bypass

if TYPE_CHECKING:
    from apps.core.models import AuditChainCheckpoint, AuditLog, Organization

logger = logging.getLogger(__name__)

GENESIS_AUDIT_HASH: str = "0" * 64
_KMS_PUBLIC_KEY_DER_CACHE: dict[tuple[str, str], bytes] = {}


def clear_kms_public_key_cache() -> None:
    """Clear the process-local AWS KMS SubjectPublicKeyInfo DER cache."""
    _KMS_PUBLIC_KEY_DER_CACHE.clear()


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(encoded: str) -> bytes:
    cleaned = encoded.strip()
    padding = "=" * ((4 - len(cleaned) % 4) % 4)
    return base64.urlsafe_b64decode((cleaned + padding).encode("ascii"))


def _normalize_pem_bytes(raw_pem: str) -> bytes:
    return raw_pem.strip().replace("\\n", "\n").encode("utf-8")


def _canonical_timestamp(dt_val: Any) -> str:
    if isinstance(dt_val, str):
        text = dt_val.strip()
        if text.endswith("Z") and len(text) == 27 and "." in text:
            return text
        normalized = text.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
        return str(parsed.astimezone(dt_timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
    if dt_val is None:
        dt_val = timezone.now()
    utc_dt = dt_val.astimezone(dt_timezone.utc)
    return str(utc_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ"))


def _anchor_signing_secret() -> bytes:
    configured = str(getattr(settings, "AUDIT_ANCHOR_SIGNING_KEY", "") or "").strip()
    if configured:
        return configured.encode("utf-8")
    fallback_secret = str(getattr(settings, "SECRET_KEY", "mltask-fallback")).encode("utf-8")
    return hmac.new(fallback_secret, b"mltask-audit-worm-anchor-v1", hashlib.sha256).digest()


def _spki_pem_and_fingerprint(public_key: Any) -> tuple[str, str]:
    spki_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    spki_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    fingerprint = hashlib.sha256(spki_der).hexdigest()
    return spki_pem, fingerprint


def _public_key_to_jwk(public_key: Any, fingerprint: str) -> dict[str, Any]:
    if isinstance(public_key, Ed25519PublicKey):
        raw_x = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "EdDSA",
            "use": "sig",
            "kid": fingerprint[:16],
            "x": _b64url_encode(raw_x),
        }
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        nums = public_key.public_numbers()
        coord_len = (public_key.key_size + 7) // 8
        return {
            "kty": "EC",
            "crv": f"P-{public_key.key_size}",
            "alg": "ES256",
            "use": "sig",
            "kid": fingerprint[:16],
            "x": _b64url_encode(nums.x.to_bytes(coord_len, "big")),
            "y": _b64url_encode(nums.y.to_bytes(coord_len, "big")),
        }
    return {"use": "sig", "kid": fingerprint[:16]}


def compute_audit_entry_hash(entry: "AuditLog") -> str:
    """Compute deterministic SHA-256 hex digest over canonical ``AuditLog`` fields."""
    canonical_doc = {
        "v": 1,
        "id": str(entry.id),
        "organization_id": str(entry.organization_id) if entry.organization_id else None,
        "user_id": str(entry.user_id) if entry.user_id else None,
        "action": str(entry.action),
        "resource_type": str(entry.resource_type),
        "resource_id": str(entry.resource_id or ""),
        "ip_address": str(entry.ip_address) if entry.ip_address else None,
        "user_agent": str(entry.user_agent or ""),
        "metadata": entry.metadata if isinstance(entry.metadata, dict) else {},
        "created_at": _canonical_timestamp(entry.created_at),
        "chain_seq": int(entry.chain_seq),
        "prev_hash": str(entry.prev_hash),
    }
    encoded = json.dumps(
        canonical_doc,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def compute_canonical_checkpoint_hash(
    *,
    checkpoint_id: str,
    organization_id: str,
    checkpoint_seq: int,
    covered_up_to_seq: int,
    verified_entries: int,
    head_hash: str,
    manifest_digest: str,
    prev_checkpoint_hash: str,
    retention_until: Any,
    created_at: Any,
) -> str:
    """Compute secret-free SHA-256 hex digest over canonical checkpoint fields."""
    envelope = {
        "v": 1,
        "id": str(checkpoint_id),
        "organization_id": str(organization_id),
        "checkpoint_seq": int(checkpoint_seq),
        "covered_up_to_seq": int(covered_up_to_seq),
        "verified_entries": int(verified_entries),
        "head_hash": str(head_hash),
        "manifest_digest": str(manifest_digest),
        "prev_checkpoint_hash": str(prev_checkpoint_hash),
        "retention_until": _canonical_timestamp(retention_until),
        "created_at": _canonical_timestamp(created_at),
    }
    canonical_bytes = json.dumps(
        envelope,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


def compute_checkpoint_hash_and_signature(
    *,
    checkpoint_id: str,
    organization_id: str,
    checkpoint_seq: int,
    covered_up_to_seq: int,
    verified_entries: int,
    head_hash: str,
    manifest_digest: str,
    prev_checkpoint_hash: str,
    retention_until: datetime,
    created_at: datetime,
) -> tuple[str, str]:
    """Return ``(checkpoint_hash, hmac_signature)`` over canonical checkpoint fields."""
    ckpt_hash = compute_canonical_checkpoint_hash(
        checkpoint_id=checkpoint_id,
        organization_id=organization_id,
        checkpoint_seq=checkpoint_seq,
        covered_up_to_seq=covered_up_to_seq,
        verified_entries=verified_entries,
        head_hash=head_hash,
        manifest_digest=manifest_digest,
        prev_checkpoint_hash=prev_checkpoint_hash,
        retention_until=retention_until,
        created_at=created_at,
    )
    sig = hmac.new(
        _anchor_signing_secret(),
        ckpt_hash.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    return ckpt_hash, sig


def _aws_sigv4_sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _aws_sigv4_signing_key(secret_key: str, date_stamp: str, region: str, service: str) -> bytes:
    k_date = _aws_sigv4_sign(("AWS4" + secret_key).encode("utf-8"), date_stamp)
    k_region = _aws_sigv4_sign(k_date, region)
    k_service = _aws_sigv4_sign(k_region, service)
    return _aws_sigv4_sign(k_service, "aws4_request")


def _kms_sigv4_json_post(
    *,
    target: str,
    payload: dict[str, Any],
    region: str,
    endpoint_host: str = "",
) -> dict[str, Any]:
    """Execute a signed AWS KMS JSON-RPC 1.1 HTTPS POST request without boto3."""
    access_key = os.getenv("AWS_ACCESS_KEY_ID", "").strip()
    secret_key = os.getenv("AWS_SECRET_ACCESS_KEY", "").strip()
    session_token = os.getenv("AWS_SESSION_TOKEN", "").strip()
    if not access_key or not secret_key:
        raise RuntimeError(
            "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are required for AWS KMS operations."
        )

    now_utc = datetime.now(dt_timezone.utc)
    amz_date = now_utc.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now_utc.strftime("%Y%m%d")
    host = endpoint_host.strip() or f"kms.{region}.amazonaws.com"
    body_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_sha256 = hashlib.sha256(body_bytes).hexdigest()

    signed_headers_map: dict[str, str] = {
        "content-type": "application/x-amz-json-1.1",
        "host": host,
        "x-amz-content-sha256": payload_sha256,
        "x-amz-date": amz_date,
        "x-amz-target": target,
    }
    if session_token:
        signed_headers_map["x-amz-security-token"] = session_token

    sorted_keys = sorted(signed_headers_map.keys())
    canonical_headers = "".join(f"{k}:{signed_headers_map[k]}\n" for k in sorted_keys)
    signed_headers_str = ";".join(sorted_keys)
    canonical_request = "\n".join(
        [
            "POST",
            "/",
            "",
            canonical_headers,
            signed_headers_str,
            payload_sha256,
        ]
    )
    credential_scope = f"{date_stamp}/{region}/kms/aws4_request"
    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amz_date,
            credential_scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )
    signing_key = _aws_sigv4_signing_key(secret_key, date_stamp, region, "kms")
    signature_hex = hmac.new(
        signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    auth_header = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers_str}, Signature={signature_hex}"
    )

    request_headers = {
        "Authorization": auth_header,
        "Content-Length": str(len(body_bytes)),
        "Content-Type": "application/x-amz-json-1.1",
        "X-Amz-Target": target,
        "x-amz-content-sha256": payload_sha256,
        "x-amz-date": amz_date,
    }
    if session_token:
        request_headers["x-amz-security-token"] = session_token

    tls_ctx = ssl.create_default_context()
    conn = http.client.HTTPSConnection(host, port=443, timeout=10.0, context=tls_ctx)
    try:
        conn.request("POST", "/", body=body_bytes, headers=request_headers)
        resp = conn.getresponse()
        resp_bytes = resp.read(16384)
        resp_text = resp_bytes.decode("utf-8", errors="replace")
        if resp.status != 200:
            raise RuntimeError(
                f"AWS KMS {target} failed with HTTP {resp.status}: {resp_text[:300]}"
            )
        parsed = json.loads(resp_text)
        return dict(parsed) if isinstance(parsed, dict) else {}
    finally:
        conn.close()


def kms_get_public_key_der(
    *,
    key_id: str,
    region: str,
    endpoint_host: str = "",
) -> bytes:
    """Fetch and memoize the DER SubjectPublicKeyInfo for an asymmetric AWS KMS key."""
    cache_key = (key_id, region)
    cached = _KMS_PUBLIC_KEY_DER_CACHE.get(cache_key)
    if cached is not None:
        return cached
    response = _kms_sigv4_json_post(
        target="TrentService.GetPublicKey",
        payload={"KeyId": key_id},
        region=region,
        endpoint_host=endpoint_host,
    )
    pub_b64 = str(response.get("PublicKey") or "").strip()
    if not pub_b64:
        raise RuntimeError("AWS KMS GetPublicKey response missing PublicKey field.")
    der_bytes = base64.b64decode(pub_b64.encode("ascii"))
    _KMS_PUBLIC_KEY_DER_CACHE[cache_key] = der_bytes
    return der_bytes


def kms_sign_checkpoint_digest(
    *,
    key_id: str,
    region: str,
    checkpoint_hash_hex: str,
    signing_algorithm: str = "ECDSA_SHA_256",
    endpoint_host: str = "",
) -> bytes:
    """Sign a 32-byte SHA-256 checkpoint digest via AWS KMS ``TrentService.Sign``."""
    digest_bytes = bytes.fromhex(checkpoint_hash_hex)
    response = _kms_sigv4_json_post(
        target="TrentService.Sign",
        payload={
            "KeyId": key_id,
            "Message": base64.b64encode(digest_bytes).decode("ascii"),
            "MessageType": "DIGEST",
            "SigningAlgorithm": signing_algorithm,
        },
        region=region,
        endpoint_host=endpoint_host,
    )
    sig_b64 = str(response.get("Signature") or "").strip()
    if not sig_b64:
        raise RuntimeError("AWS KMS Sign response missing Signature field.")
    return base64.b64decode(sig_b64.encode("ascii"))


def _resolve_verification_public_key() -> Any | None:
    """Resolve the active verification public key (PEM pin, Ed25519 keypair, or KMS key)."""
    pinned_pub_pem = str(getattr(settings, "AUDIT_ANCHOR_PUBLIC_KEY_PEM", "") or "").strip()
    if pinned_pub_pem:
        return serialization.load_pem_public_key(_normalize_pem_bytes(pinned_pub_pem))

    ed_priv_pem = str(getattr(settings, "AUDIT_ANCHOR_ED25519_PRIVATE_KEY_PEM", "") or "").strip()
    if ed_priv_pem:
        priv = serialization.load_pem_private_key(_normalize_pem_bytes(ed_priv_pem), password=None)
        if isinstance(priv, Ed25519PrivateKey):
            return priv.public_key()

    kms_key_id = str(getattr(settings, "AUDIT_ANCHOR_KMS_KEY_ID", "") or "").strip()
    if kms_key_id:
        region = str(getattr(settings, "AUDIT_WORM_S3_REGION", "us-east-1") or "us-east-1").strip()
        kms_host = str(getattr(settings, "AUDIT_ANCHOR_KMS_ENDPOINT_HOST", "") or "").strip()
        der_bytes = kms_get_public_key_der(
            key_id=kms_key_id,
            region=region,
            endpoint_host=kms_host,
        )
        return serialization.load_der_public_key(der_bytes)

    return None


def get_active_transparency_public_key_metadata() -> dict[str, Any]:
    """Return active asymmetric public-key PEM, SHA-256 fingerprint, and RFC 7517/8037 JWK."""
    kms_key_id = str(getattr(settings, "AUDIT_ANCHOR_KMS_KEY_ID", "") or "").strip()
    pub_key = _resolve_verification_public_key()
    if pub_key is None:
        return {
            "asymmetric_signing_enabled": False,
            "signature_algorithm": "HMAC-SHA256",
            "public_key_fingerprint": "",
            "public_key_pem": "",
            "jwk": None,
            "kms_key_configured": bool(kms_key_id),
        }

    spki_pem, fingerprint = _spki_pem_and_fingerprint(pub_key)
    sig_alg = "Ed25519" if isinstance(pub_key, Ed25519PublicKey) else "KMS-ECDSA-SHA256"
    return {
        "asymmetric_signing_enabled": True,
        "signature_algorithm": sig_alg,
        "public_key_fingerprint": fingerprint,
        "public_key_pem": spki_pem,
        "jwk": _public_key_to_jwk(pub_key, fingerprint),
        "kms_key_configured": bool(kms_key_id),
    }


def sign_checkpoint_asymmetrically(checkpoint_hash: str) -> tuple[str, str, str]:
    """Return ``(signature_algorithm, public_key_fingerprint, asymmetric_signature)``."""
    kms_key_id = str(getattr(settings, "AUDIT_ANCHOR_KMS_KEY_ID", "") or "").strip()
    if kms_key_id:
        region = str(getattr(settings, "AUDIT_WORM_S3_REGION", "us-east-1") or "us-east-1").strip()
        kms_alg = str(
            getattr(settings, "AUDIT_ANCHOR_KMS_SIGNING_ALG", "ECDSA_SHA_256") or "ECDSA_SHA_256"
        ).strip()
        kms_host = str(getattr(settings, "AUDIT_ANCHOR_KMS_ENDPOINT_HOST", "") or "").strip()
        sig_bytes = kms_sign_checkpoint_digest(
            key_id=kms_key_id,
            region=region,
            checkpoint_hash_hex=checkpoint_hash,
            signing_algorithm=kms_alg,
            endpoint_host=kms_host,
        )
        pinned_pub = str(getattr(settings, "AUDIT_ANCHOR_PUBLIC_KEY_PEM", "") or "").strip()
        if pinned_pub:
            pub_obj: Any = serialization.load_pem_public_key(_normalize_pem_bytes(pinned_pub))
        else:
            der_bytes = kms_get_public_key_der(
                key_id=kms_key_id,
                region=region,
                endpoint_host=kms_host,
            )
            pub_obj = serialization.load_der_public_key(der_bytes)
        _pem, fingerprint = _spki_pem_and_fingerprint(pub_obj)
        return "KMS-ECDSA-SHA256", fingerprint, _b64url_encode(sig_bytes)

    ed_priv_pem = str(getattr(settings, "AUDIT_ANCHOR_ED25519_PRIVATE_KEY_PEM", "") or "").strip()
    if ed_priv_pem:
        priv = serialization.load_pem_private_key(_normalize_pem_bytes(ed_priv_pem), password=None)
        if not isinstance(priv, Ed25519PrivateKey):
            raise ValueError("AUDIT_ANCHOR_ED25519_PRIVATE_KEY_PEM must be an Ed25519 private key.")
        sig_bytes = priv.sign(checkpoint_hash.encode("ascii"))
        _pem, fingerprint = _spki_pem_and_fingerprint(priv.public_key())
        return "Ed25519", fingerprint, _b64url_encode(sig_bytes)

    return "HMAC-SHA256", "", ""


def _verify_signature_with_public_key(
    *,
    public_key: Any,
    checkpoint_hash: str,
    signature_algorithm: str,
    asymmetric_signature: str,
    expected_fingerprint: str,
) -> list[str]:
    reasons: list[str] = []
    _pem, actual_fingerprint = _spki_pem_and_fingerprint(public_key)
    if expected_fingerprint and not hmac.compare_digest(actual_fingerprint, expected_fingerprint):
        reasons.append("checkpoint_public_key_mismatch")

    if not asymmetric_signature:
        reasons.append("checkpoint_asymmetric_signature_mismatch")
        return reasons

    try:
        raw_sig = _b64url_decode(asymmetric_signature)
        if signature_algorithm == "Ed25519":
            if not isinstance(public_key, Ed25519PublicKey):
                reasons.append("checkpoint_public_key_mismatch")
                return reasons
            public_key.verify(raw_sig, checkpoint_hash.encode("ascii"))
        elif signature_algorithm == "KMS-ECDSA-SHA256":
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                reasons.append("checkpoint_public_key_mismatch")
                return reasons
            public_key.verify(
                raw_sig,
                bytes.fromhex(checkpoint_hash),
                ec.ECDSA(asym_utils.Prehashed(hashes.SHA256())),
            )
        else:
            reasons.append("checkpoint_asymmetric_signature_mismatch")
    except (InvalidSignature, ValueError):
        reasons.append("checkpoint_asymmetric_signature_mismatch")

    return reasons


def verify_checkpoint_offline_bundle(
    checkpoint_data: dict[str, Any],
    public_key_pem: str,
) -> dict[str, Any]:
    """Verify a notarized checkpoint JSON offline using ONLY ``public_key_pem`` (zero secrets)."""
    org_id = str(
        checkpoint_data.get("organization_id") or checkpoint_data.get("organization") or ""
    )
    recomputed_hash = compute_canonical_checkpoint_hash(
        checkpoint_id=str(checkpoint_data["id"]),
        organization_id=org_id,
        checkpoint_seq=int(checkpoint_data["checkpoint_seq"]),
        covered_up_to_seq=int(checkpoint_data["covered_up_to_seq"]),
        verified_entries=int(checkpoint_data["verified_entries"]),
        head_hash=str(checkpoint_data["head_hash"]),
        manifest_digest=str(checkpoint_data["manifest_digest"]),
        prev_checkpoint_hash=str(checkpoint_data["prev_checkpoint_hash"]),
        retention_until=checkpoint_data["retention_until"],
        created_at=checkpoint_data["created_at"],
    )

    reasons: list[str] = []
    claimed_hash = str(checkpoint_data.get("checkpoint_hash") or "")
    if not hmac.compare_digest(claimed_hash, recomputed_hash):
        reasons.append("checkpoint_hash_mismatch")

    pub_key = serialization.load_pem_public_key(_normalize_pem_bytes(public_key_pem))
    _pem, actual_fp = _spki_pem_and_fingerprint(pub_key)
    sig_alg = str(checkpoint_data.get("signature_algorithm") or "HMAC-SHA256")
    asym_sig = str(checkpoint_data.get("asymmetric_signature") or "")
    expected_fp = str(checkpoint_data.get("public_key_fingerprint") or "")

    sig_reasons = _verify_signature_with_public_key(
        public_key=pub_key,
        checkpoint_hash=recomputed_hash,
        signature_algorithm=sig_alg,
        asymmetric_signature=asym_sig,
        expected_fingerprint=expected_fp,
    )
    reasons.extend(sig_reasons)

    return {
        "valid": len(reasons) == 0,
        "recomputed_checkpoint_hash": recomputed_hash,
        "public_key_fingerprint": actual_fp,
        "signature_algorithm": sig_alg,
        "reasons": reasons,
    }


def upload_worm_checkpoint_to_s3(
    *,
    bucket: str,
    region: str,
    object_key: str,
    payload_bytes: bytes,
    retain_until: datetime,
    endpoint_host: str = "",
) -> dict[str, str]:
    """Upload checkpoint JSON to S3 with Object Lock ``COMPLIANCE`` retention via AWS SigV4."""
    access_key = os.getenv("AWS_ACCESS_KEY_ID", "").strip()
    secret_key = os.getenv("AWS_SECRET_ACCESS_KEY", "").strip()
    session_token = os.getenv("AWS_SESSION_TOKEN", "").strip()
    if not access_key or not secret_key:
        raise RuntimeError(
            "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are required for S3 WORM upload."
        )

    now_utc = datetime.now(dt_timezone.utc)
    amz_date = now_utc.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now_utc.strftime("%Y%m%d")
    retain_iso = retain_until.astimezone(dt_timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    host = endpoint_host.strip() or f"{bucket}.s3.{region}.amazonaws.com"
    canonical_uri = "/" + "/".join(
        quote(part, safe="-_.~") for part in object_key.lstrip("/").split("/")
    )
    payload_sha256 = hashlib.sha256(payload_bytes).hexdigest()
    content_md5 = base64.b64encode(
        hashlib.md5(payload_bytes, usedforsecurity=False).digest()
    ).decode("ascii")

    signed_headers_map: dict[str, str] = {
        "content-md5": content_md5,
        "content-type": "application/json",
        "host": host,
        "x-amz-content-sha256": payload_sha256,
        "x-amz-date": amz_date,
        "x-amz-object-lock-mode": "COMPLIANCE",
        "x-amz-object-lock-retain-until-date": retain_iso,
    }
    if session_token:
        signed_headers_map["x-amz-security-token"] = session_token

    sorted_header_keys = sorted(signed_headers_map.keys())
    canonical_headers = "".join(f"{k}:{signed_headers_map[k]}\n" for k in sorted_header_keys)
    signed_headers_str = ";".join(sorted_header_keys)

    canonical_request = "\n".join(
        [
            "PUT",
            canonical_uri,
            "",
            canonical_headers,
            signed_headers_str,
            payload_sha256,
        ]
    )
    credential_scope = f"{date_stamp}/{region}/s3/aws4_request"
    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amz_date,
            credential_scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )
    signing_key = _aws_sigv4_signing_key(secret_key, date_stamp, region, "s3")
    signature_hex = hmac.new(
        signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    auth_header = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers_str}, Signature={signature_hex}"
    )

    request_headers = {
        "Authorization": auth_header,
        "Content-Length": str(len(payload_bytes)),
        "Content-MD5": content_md5,
        "Content-Type": "application/json",
        "x-amz-content-sha256": payload_sha256,
        "x-amz-date": amz_date,
        "x-amz-object-lock-mode": "COMPLIANCE",
        "x-amz-object-lock-retain-until-date": retain_iso,
    }
    if session_token:
        request_headers["x-amz-security-token"] = session_token

    tls_ctx = ssl.create_default_context()
    conn = http.client.HTTPSConnection(host, port=443, timeout=10.0, context=tls_ctx)
    try:
        conn.request("PUT", canonical_uri, body=payload_bytes, headers=request_headers)
        resp = conn.getresponse()
        resp_body = resp.read(2048).decode("utf-8", errors="replace")
        if resp.status not in (200, 201):
            raise RuntimeError(f"S3 WORM PUT failed with HTTP {resp.status}: {resp_body[:300]}")
        etag = (resp.getheader("ETag") or "").strip('"')
        version_id = (resp.getheader("x-amz-version-id") or "").strip()
        return {
            "worm_uri": f"s3://{bucket}/{object_key.lstrip('/')}",
            "etag": etag,
            "version_id": version_id,
        }
    finally:
        conn.close()


def seal_and_insert_audit_log(
    entry: "AuditLog",
    raw_save: Callable[..., None],
    *args: Any,
    **kwargs: Any,
) -> None:
    """Atomically advance the tenant/global audit hash chain and persist ``entry``."""
    from apps.core.models import AuditLog

    target_db = str(kwargs.get("using") or "default")
    entry.created_at = (entry.created_at or timezone.now()).astimezone(dt_timezone.utc)
    if entry.ip_address is not None:
        entry.ip_address = str(entry.ip_address)
    if entry.metadata is None:
        entry.metadata = {}

    lock_scope = str(entry.organization_id) if entry.organization_id else "global"

    with transaction.atomic(using=target_db):
        with rls_bypass(using=target_db):
            conn = connections[target_db]
            if getattr(conn, "vendor", "") == "postgresql":
                with conn.cursor() as cursor:
                    cursor.execute(
                        "SELECT pg_advisory_xact_lock(hashtext(%s))",
                        [f"mltask_audit:{lock_scope}"],
                    )

            if entry.organization_id:
                scope_qs = AuditLog.objects.using(target_db).filter(
                    organization_id=entry.organization_id
                )
            else:
                scope_qs = AuditLog.objects.using(target_db).filter(organization__isnull=True)

            head = scope_qs.order_by("-chain_seq").values_list("chain_seq", "entry_hash").first()
            if head and int(head[0]) > 0 and head[1]:
                prev_seq = int(head[0])
                prev_digest = str(head[1])
            else:
                prev_seq = 0
                prev_digest = GENESIS_AUDIT_HASH

            entry.chain_seq = prev_seq + 1
            entry.prev_hash = prev_digest
            entry.entry_hash = compute_audit_entry_hash(entry)
            raw_save(*args, **kwargs)


def verify_organization_audit_chain(
    org: "Organization",
    *,
    force_primary: bool = False,
) -> tuple[dict[str, Any], str]:
    """Verify cryptographic hash-chain continuity, HMAC, Ed25519/KMS & WORM checkpoints."""
    from apps.core.models import AuditChainCheckpoint, AuditLog

    violations: list[dict[str, Any]] = []
    checkpoint_violations: list[dict[str, Any]] = []
    expected_seq = 1
    expected_prev = GENESIS_AUDIT_HASH
    head_hash = GENESIS_AUDIT_HASH
    max_chain_seq = 0
    verified_count = 0

    if force_primary:
        query_target = "primary"
        entries = list(AuditLog.objects.filter(organization_id=org.id).order_by("chain_seq", "id"))
        checkpoints = list(
            AuditChainCheckpoint.objects.filter(organization_id=org.id).order_by(
                "checkpoint_seq", "id"
            )
        )
    else:
        with use_read_replica() as query_target:
            entries = list(
                AuditLog.objects.filter(organization_id=org.id).order_by("chain_seq", "id")
            )
            checkpoints = list(
                AuditChainCheckpoint.objects.filter(organization_id=org.id).order_by(
                    "checkpoint_seq", "id"
                )
            )

    hash_by_seq: dict[int, str] = {}
    for item in entries:
        verified_count += 1
        reasons: list[str] = []

        if int(item.chain_seq) != expected_seq:
            reasons.append("sequence_gap")

        if not hmac.compare_digest(str(item.prev_hash), expected_prev):
            reasons.append("prev_hash_mismatch")

        recomputed = compute_audit_entry_hash(item)
        if not hmac.compare_digest(str(item.entry_hash), recomputed):
            reasons.append("entry_hash_mismatch")

        if reasons:
            violations.append(
                {
                    "id": str(item.id),
                    "chain_seq": int(item.chain_seq),
                    "expected_seq": expected_seq,
                    "reasons": reasons,
                }
            )

        seq_int = int(item.chain_seq)
        hash_by_seq[seq_int] = str(item.entry_hash)
        max_chain_seq = max(max_chain_seq, seq_int)
        head_hash = str(item.entry_hash or recomputed)
        expected_prev = str(item.entry_hash)
        expected_seq = seq_int + 1

    active_pub_key: Any | None = None
    has_asymmetric = any(
        str(c.signature_algorithm) != "HMAC-SHA256" or bool(c.asymmetric_signature)
        for c in checkpoints
    )
    if has_asymmetric:
        try:
            active_pub_key = _resolve_verification_public_key()
        except Exception as exc:
            logger.warning("Failed to resolve transparency public key: %s", exc)
            active_pub_key = None

    expected_ckpt_seq = 1
    expected_prev_ckpt_hash = GENESIS_AUDIT_HASH
    for ckpt in checkpoints:
        ckpt_reasons: list[str] = []
        if int(ckpt.checkpoint_seq) != expected_ckpt_seq:
            ckpt_reasons.append("checkpoint_sequence_gap")

        if not hmac.compare_digest(str(ckpt.prev_checkpoint_hash), expected_prev_ckpt_hash):
            ckpt_reasons.append("checkpoint_prev_hash_mismatch")

        exp_hash, exp_sig = compute_checkpoint_hash_and_signature(
            checkpoint_id=str(ckpt.id),
            organization_id=str(ckpt.organization_id),
            checkpoint_seq=int(ckpt.checkpoint_seq),
            covered_up_to_seq=int(ckpt.covered_up_to_seq),
            verified_entries=int(ckpt.verified_entries),
            head_hash=str(ckpt.head_hash),
            manifest_digest=str(ckpt.manifest_digest),
            prev_checkpoint_hash=str(ckpt.prev_checkpoint_hash),
            retention_until=ckpt.retention_until,
            created_at=ckpt.created_at,
        )
        if not hmac.compare_digest(str(ckpt.checkpoint_hash), exp_hash):
            ckpt_reasons.append("checkpoint_hash_mismatch")
        if not hmac.compare_digest(str(ckpt.signature), exp_sig):
            ckpt_reasons.append("checkpoint_signature_mismatch")

        sig_alg = str(ckpt.signature_algorithm or "HMAC-SHA256")
        if sig_alg != "HMAC-SHA256" or ckpt.asymmetric_signature:
            if active_pub_key is None:
                ckpt_reasons.append("checkpoint_public_key_unavailable")
            else:
                asym_reasons = _verify_signature_with_public_key(
                    public_key=active_pub_key,
                    checkpoint_hash=exp_hash,
                    signature_algorithm=sig_alg,
                    asymmetric_signature=str(ckpt.asymmetric_signature),
                    expected_fingerprint=str(ckpt.public_key_fingerprint),
                )
                ckpt_reasons.extend(asym_reasons)

        anchored_seq = int(ckpt.covered_up_to_seq)
        if anchored_seq > 0:
            observed_hash = hash_by_seq.get(anchored_seq)
            if observed_hash is None or not hmac.compare_digest(observed_hash, str(ckpt.head_hash)):
                ckpt_reasons.append("checkpoint_anchor_divergence")

        if ckpt_reasons:
            checkpoint_violations.append(
                {
                    "checkpoint_id": str(ckpt.id),
                    "checkpoint_seq": int(ckpt.checkpoint_seq),
                    "covered_up_to_seq": anchored_seq,
                    "reasons": ckpt_reasons,
                }
            )

        expected_prev_ckpt_hash = str(ckpt.checkpoint_hash)
        expected_ckpt_seq = int(ckpt.checkpoint_seq) + 1

    chain_valid = len(violations) == 0 and len(checkpoint_violations) == 0
    manifest_preimage = json.dumps(
        {
            "organization_id": str(org.id),
            "verified_entries": verified_count,
            "genesis_hash": GENESIS_AUDIT_HASH,
            "head_hash": head_hash,
            "valid": chain_valid,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    manifest_digest = hashlib.sha256(manifest_preimage).hexdigest()
    latest_ckpt = checkpoints[-1] if checkpoints else None

    report: dict[str, Any] = {
        "organization_id": str(org.id),
        "valid": chain_valid,
        "verified_entries": verified_count,
        "head_chain_seq": max_chain_seq,
        "genesis_hash": GENESIS_AUDIT_HASH,
        "head_hash": head_hash,
        "manifest_digest": manifest_digest,
        "verified_at": _canonical_timestamp(timezone.now()),
        "violations": violations,
        "checkpoint_valid": len(checkpoint_violations) == 0,
        "checkpoints_verified": len(checkpoints),
        "checkpoint_violations": checkpoint_violations,
        "latest_checkpoint_seq": int(latest_ckpt.checkpoint_seq) if latest_ckpt else None,
        "latest_signature_algorithm": (
            str(latest_ckpt.signature_algorithm) if latest_ckpt else None
        ),
        "latest_worm_uri": (
            str(latest_ckpt.worm_uri) if latest_ckpt and latest_ckpt.worm_uri else None
        ),
        "first_corrupted_seq": violations[0]["chain_seq"] if violations else None,
        "first_corrupted_id": violations[0]["id"] if violations else None,
        "query_target": query_target,
    }
    return report, query_target


def create_organization_audit_checkpoint(
    org: "Organization",
    *,
    force: bool = False,
) -> tuple["AuditChainCheckpoint | None", bool]:
    """Verify ``org``'s AuditLog chain and persist an HMAC + Ed25519/KMS + S3 WORM checkpoint."""
    import uuid as uuid_mod

    from apps.core.models import AuditChainCheckpoint
    from apps.core.outbox import enqueue_outbox_event

    report, _ = verify_organization_audit_chain(org, force_primary=True)
    if not report["valid"]:
        raise ValidationError(
            "Cannot anchor audit checkpoint: underlying AuditLog chain failed verification."
        )

    verified_entries = int(report["verified_entries"])
    covered_seq = int(report["head_chain_seq"])
    if verified_entries == 0 and not force:
        return None, False

    retention_days = max(1, int(getattr(settings, "AUDIT_WORM_RETENTION_DAYS", 365)))
    now_utc = timezone.now().astimezone(dt_timezone.utc)
    retention_until = now_utc + timedelta(days=retention_days)
    bucket = str(getattr(settings, "AUDIT_WORM_S3_BUCKET", "") or "").strip()
    region = str(getattr(settings, "AUDIT_WORM_S3_REGION", "us-east-1") or "us-east-1").strip()
    endpoint_host = str(getattr(settings, "AUDIT_WORM_S3_ENDPOINT_HOST", "") or "").strip()

    with transaction.atomic():
        with rls_bypass():
            conn = connections["default"]
            if getattr(conn, "vendor", "") == "postgresql":
                with conn.cursor() as cursor:
                    cursor.execute(
                        "SELECT pg_advisory_xact_lock(hashtext(%s))",
                        [f"mltask_audit_ckpt:{org.id}"],
                    )

            latest = (
                AuditChainCheckpoint.objects.filter(organization_id=org.id)
                .order_by("-checkpoint_seq")
                .first()
            )
            if (
                latest is not None
                and not force
                and int(latest.covered_up_to_seq) == covered_seq
                and str(latest.head_hash) == str(report["head_hash"])
            ):
                return latest, False

            next_ckpt_seq = (int(latest.checkpoint_seq) + 1) if latest is not None else 1
            prev_ckpt_hash = (
                str(latest.checkpoint_hash) if latest is not None else GENESIS_AUDIT_HASH
            )
            ckpt_id = uuid_mod.uuid4()

            ckpt_hash, sig = compute_checkpoint_hash_and_signature(
                checkpoint_id=str(ckpt_id),
                organization_id=str(org.id),
                checkpoint_seq=next_ckpt_seq,
                covered_up_to_seq=covered_seq,
                verified_entries=verified_entries,
                head_hash=str(report["head_hash"]),
                manifest_digest=str(report["manifest_digest"]),
                prev_checkpoint_hash=prev_ckpt_hash,
                retention_until=retention_until,
                created_at=now_utc,
            )

            anchor_status = "hmac_sealed"
            worm_uri = ""
            worm_etag = ""
            worm_version_id = ""
            anchor_error = ""
            sig_algorithm = "HMAC-SHA256"
            pub_fingerprint = ""
            asym_signature = ""

            try:
                sig_algorithm, pub_fingerprint, asym_signature = sign_checkpoint_asymmetrically(
                    ckpt_hash
                )
            except Exception as exc:
                anchor_status = "anchor_error"
                anchor_error = f"Asymmetric signing error: {str(exc)[:420]}"
                logger.error(
                    "Failed asymmetric signing for audit checkpoint org=%s seq=%s: %s",
                    org.id,
                    next_ckpt_seq,
                    anchor_error,
                )

            if bucket:
                object_key = (
                    f"audit-checkpoints/{org.id}/"
                    f"seq-{next_ckpt_seq:08d}-{str(report['head_hash'])[:12]}.json"
                )
                worm_doc = json.dumps(
                    {
                        "id": str(ckpt_id),
                        "organization_id": str(org.id),
                        "checkpoint_seq": next_ckpt_seq,
                        "covered_up_to_seq": covered_seq,
                        "verified_entries": verified_entries,
                        "head_hash": report["head_hash"],
                        "manifest_digest": report["manifest_digest"],
                        "prev_checkpoint_hash": prev_ckpt_hash,
                        "checkpoint_hash": ckpt_hash,
                        "signature": sig,
                        "signature_algorithm": sig_algorithm,
                        "public_key_fingerprint": pub_fingerprint,
                        "asymmetric_signature": asym_signature,
                        "retention_until": _canonical_timestamp(retention_until),
                        "created_at": _canonical_timestamp(now_utc),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                try:
                    s3_meta = upload_worm_checkpoint_to_s3(
                        bucket=bucket,
                        region=region,
                        object_key=object_key,
                        payload_bytes=worm_doc,
                        retain_until=retention_until,
                        endpoint_host=endpoint_host,
                    )
                    if anchor_status != "anchor_error":
                        anchor_status = "s3_worm_locked"
                    worm_uri = s3_meta["worm_uri"]
                    worm_etag = s3_meta["etag"]
                    worm_version_id = s3_meta["version_id"]
                except Exception as exc:
                    anchor_status = "anchor_error"
                    s3_err = str(exc)[:480]
                    anchor_error = f"{anchor_error}; {s3_err}".strip("; ")[:500]
                    logger.error(
                        "Failed to upload WORM audit checkpoint for org=%s seq=%s: %s",
                        org.id,
                        next_ckpt_seq,
                        anchor_error,
                    )

            checkpoint = AuditChainCheckpoint.objects.create(
                id=ckpt_id,
                organization=org,
                checkpoint_seq=next_ckpt_seq,
                covered_up_to_seq=covered_seq,
                verified_entries=verified_entries,
                head_hash=str(report["head_hash"]),
                manifest_digest=str(report["manifest_digest"]),
                prev_checkpoint_hash=prev_ckpt_hash,
                checkpoint_hash=ckpt_hash,
                signature=sig,
                signature_algorithm=sig_algorithm,
                public_key_fingerprint=pub_fingerprint,
                asymmetric_signature=asym_signature,
                anchor_status=anchor_status,
                worm_uri=worm_uri,
                worm_etag=worm_etag,
                worm_version_id=worm_version_id,
                retention_until=retention_until,
                anchor_error=anchor_error,
                created_at=now_utc,
            )

            enqueue_outbox_event(
                organization_id=str(org.id),
                event_type="audit.checkpoint_anchored",
                payload={
                    "checkpoint_id": str(checkpoint.id),
                    "checkpoint_seq": next_ckpt_seq,
                    "covered_up_to_seq": covered_seq,
                    "head_hash": checkpoint.head_hash,
                    "checkpoint_hash": checkpoint.checkpoint_hash,
                    "signature": checkpoint.signature,
                    "signature_algorithm": checkpoint.signature_algorithm,
                    "public_key_fingerprint": checkpoint.public_key_fingerprint,
                    "asymmetric_signature": checkpoint.asymmetric_signature,
                    "anchor_status": checkpoint.anchor_status,
                    "worm_uri": checkpoint.worm_uri,
                },
            )
            return checkpoint, True


def anchor_pending_audit_checkpoints(*, batch_size: int = 100) -> dict[str, int]:
    """Periodic Celery Beat Sweep notarizing new AuditLog entries across active tenants."""
    from apps.core.models import Organization

    anchored = 0
    skipped = 0
    corrupted = 0

    with rls_bypass():
        orgs = list(
            Organization.objects.filter(is_active=True, audit_logs__isnull=False)
            .distinct()
            .order_by("created_at")[: max(1, int(batch_size))]
        )

    for org in orgs:
        with rls_bypass():
            try:
                _ckpt, created = create_organization_audit_checkpoint(org, force=False)
                if created:
                    anchored += 1
                else:
                    skipped += 1
            except ValidationError:
                corrupted += 1
                logger.error(
                    "Audit chain tamper detected during checkpoint sweep: org=%s",
                    org.id,
                )

    return {"anchored": anchored, "skipped": skipped, "corrupted": corrupted}
