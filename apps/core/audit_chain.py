"""Cryptographic SHA-256 hash-chaining and tamper verification for AuditLog records.

Each ``AuditLog`` row is sealed at insert time with:
    - ``chain_seq``: strictly monotonic 1-based sequence number within its tenant chain
      (or the ``global`` chain when ``organization_id`` is ``NULL``).
    - ``prev_hash``: ``entry_hash`` of row ``chain_seq - 1`` (``"0" * 64`` at genesis).
    - ``entry_hash``: deterministic SHA-256 hex digest over canonical JSON of all
      security-relevant columns plus ``(chain_seq, prev_hash)``.

Concurrent writers on PostgreSQL 16 serialize chain-head advancement per tenant via
transaction-scoped ``pg_advisory_xact_lock(hashtext(...))`` without contending on
``core_organization`` row locks.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Callable
from datetime import timezone as dt_timezone
from typing import TYPE_CHECKING, Any

from django.db import connections, transaction
from django.utils import timezone

from apps.core.db_router import use_read_replica
from apps.core.rls import rls_bypass

if TYPE_CHECKING:
    from apps.core.models import AuditLog, Organization

GENESIS_AUDIT_HASH: str = "0" * 64


def _canonical_timestamp(dt_val: Any) -> str:
    if dt_val is None:
        dt_val = timezone.now()
    utc_dt = dt_val.astimezone(dt_timezone.utc)
    return str(utc_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ"))


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


def verify_organization_audit_chain(org: "Organization") -> tuple[dict[str, Any], str]:
    """Verify cryptographic hash-chain continuity and payload integrity for ``org``."""
    from apps.core.models import AuditLog

    violations: list[dict[str, Any]] = []
    expected_seq = 1
    expected_prev = GENESIS_AUDIT_HASH
    head_hash = GENESIS_AUDIT_HASH
    verified_count = 0

    with use_read_replica() as query_target:
        entries = list(AuditLog.objects.filter(organization_id=org.id).order_by("chain_seq", "id"))

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

        head_hash = str(item.entry_hash or recomputed)
        expected_prev = str(item.entry_hash)
        expected_seq = int(item.chain_seq) + 1

    manifest_preimage = json.dumps(
        {
            "organization_id": str(org.id),
            "verified_entries": verified_count,
            "genesis_hash": GENESIS_AUDIT_HASH,
            "head_hash": head_hash,
            "valid": len(violations) == 0,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    manifest_digest = hashlib.sha256(manifest_preimage).hexdigest()

    report: dict[str, Any] = {
        "organization_id": str(org.id),
        "valid": len(violations) == 0,
        "verified_entries": verified_count,
        "genesis_hash": GENESIS_AUDIT_HASH,
        "head_hash": head_hash,
        "manifest_digest": manifest_digest,
        "verified_at": _canonical_timestamp(timezone.now()),
        "violations": violations,
        "first_corrupted_seq": violations[0]["chain_seq"] if violations else None,
        "first_corrupted_id": violations[0]["id"] if violations else None,
        "query_target": query_target,
    }
    return report, query_target
