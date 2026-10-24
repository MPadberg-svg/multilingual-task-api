"""Cryptographic SHA-256 hash-chaining, WORM S3 Object-Lock anchoring & tamper verification.

Each ``AuditLog`` row is sealed at insert time with:
    - ``chain_seq``: strictly monotonic 1-based sequence number within its tenant chain
      (or the ``global`` chain when ``organization_id`` is ``NULL``).
    - ``prev_hash``: ``entry_hash`` of row ``chain_seq - 1`` (``"0" * 64`` at genesis).
    - ``entry_hash``: deterministic SHA-256 hex digest over canonical JSON of all
      security-relevant columns plus ``(chain_seq, prev_hash)``.

``AuditChainCheckpoint`` rows notarize periodic snapshots of each tenant's hash chain with
a domain-separated HMAC-SHA256 signature and optional Amazon S3 Object Lock (``COMPLIANCE``
mode) WORM archival via zero-dependency AWS Signature Version 4 HTTPS ``PUT`` requests,
detecting even privileged database root-replacement or tail-truncation attacks.
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

from apps.core.db_router import use_read_replica
from apps.core.rls import rls_bypass

if TYPE_CHECKING:
    from apps.core.models import AuditChainCheckpoint, AuditLog, Organization

logger = logging.getLogger(__name__)

GENESIS_AUDIT_HASH: str = "0" * 64


def _canonical_timestamp(dt_val: Any) -> str:
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
    ckpt_hash = hashlib.sha256(canonical_bytes).hexdigest()
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
    """Verify cryptographic hash-chain continuity, payload integrity & WORM checkpoints."""
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
    """Verify ``org``'s AuditLog chain and persist an HMAC-signed + optional S3 WORM checkpoint.

    Returns ``(checkpoint, created_new)``. Raises ``ValidationError`` if the chain has any
    tamper violations so a corrupted log can never be notarized as valid.
    """
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
                    anchor_status = "s3_worm_locked"
                    worm_uri = s3_meta["worm_uri"]
                    worm_etag = s3_meta["etag"]
                    worm_version_id = s3_meta["version_id"]
                except Exception as exc:
                    anchor_status = "anchor_error"
                    anchor_error = str(exc)[:480]
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
