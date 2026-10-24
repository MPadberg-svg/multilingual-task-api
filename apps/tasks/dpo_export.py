"""DPO / RLHF preference dataset export pipeline, PII scrubbing & signed provenance manifests.

Transforms consensus-verified and expert-adjudicated ``Task`` + ``TaskAnnotation`` records
into post-training preference pairs (TRL ``DPOTrainer`` / OpenAI chat ``messages`` schemas)
with:
    - Quality gates (consensus score floor, non-empty candidate pairs, gold-trap exclusion)
    - Deterministic HMAC-SHA256 ``train`` / ``eval`` hash splits (zero train/eval leakage)
    - Regex PII / credential scrubbing across prompts, responses, and rationales
    - RFC 9162 binary Merkle root + Ed25519 / AWS KMS ECDSA-SHA256 signed provenance manifest
    - Optional zero-dependency AWS SigV4 HTTPS ``PUT`` archival to S3
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import os
import re
import ssl
from collections.abc import Mapping, Sequence
from datetime import datetime
from datetime import timezone as dt_timezone
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from django.utils import timezone

from cryptography.hazmat.primitives import serialization

from apps.core.audit_chain import (
    _anchor_signing_secret,
    _aws_sigv4_signing_key,
    _canonical_timestamp,
    _normalize_pem_bytes,
    _spki_pem_and_fingerprint,
    _verify_signature_with_public_key,
    sign_checkpoint_asymmetrically,
)
from apps.core.merkle import compute_merkle_root
from apps.tasks.calibration import resolve_effective_skill_weight

if TYPE_CHECKING:
    from apps.tasks.models import AnnotatorCalibration, Task, TaskAnnotation

_SECRET_TOKEN_RE = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{16,}|mlk_live_[A-Za-z0-9_-]{12,}|scim_live_[A-Za-z0-9_-]{12,})\b"
)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_PHONE_RE = re.compile(r"(?<!\w)(?:\+\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\w)")
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")


def scrub_dataset_pii(text: str) -> tuple[str, int]:
    """Redact credentials, emails, SSNs, phone numbers, and IPv4 addresses from ``text``."""
    if not text:
        return "", 0

    total_redactions = 0
    current = text
    for pattern, token in (
        (_SECRET_TOKEN_RE, "[REDACTED_SECRET]"),
        (_EMAIL_RE, "[REDACTED_EMAIL]"),
        (_SSN_RE, "[REDACTED_SSN]"),
        (_PHONE_RE, "[REDACTED_PHONE]"),
        (_IPV4_RE, "[REDACTED_IP]"),
    ):
        current, count = pattern.subn(token, current)
        total_redactions += count

    return current, total_redactions


def assign_deterministic_split(
    task_id: str,
    *,
    eval_ratio: float = 0.10,
    split_seed: str = "v1",
) -> str:
    """Deterministically assign ``task_id`` to ``'eval'`` or ``'train'`` via HMAC-SHA256."""
    clamped_ratio = min(0.50, max(0.0, float(eval_ratio)))
    if clamped_ratio <= 0.0:
        return "train"
    digest = hmac.new(
        str(split_seed or "v1").encode("utf-8"),
        str(task_id).encode("utf-8"),
        hashlib.sha256,
    ).digest()
    bucket = int.from_bytes(digest[:8], "big") / float(1 << 64)
    return "eval" if bucket < clamped_ratio else "train"


def _extract_candidate_pair(
    annotations: Sequence["TaskAnnotation"],
    winning_choice: str,
) -> tuple[str, str, list[str]]:
    """Extract canonical ``(response_a, response_b, winning_rationales)`` from annotations."""
    resp_a = ""
    resp_b = ""
    rationales: list[str] = []

    ordered = sorted(
        annotations,
        key=lambda a: (0 if a.preference == winning_choice else 1, a.created_at),
    )
    for ann in ordered:
        cand_a = str(ann.response_a or "").strip()
        cand_b = str(ann.response_b or "").strip()
        if cand_a and cand_b and not (resp_a and resp_b):
            resp_a = cand_a
            resp_b = cand_b
        if ann.preference == winning_choice and ann.rationale and ann.rationale.strip():
            rationales.append(ann.rationale.strip())

    if not resp_a or not resp_b:
        for ann in annotations:
            if not resp_a and ann.response_a and ann.response_a.strip():
                resp_a = ann.response_a.strip()
            if not resp_b and ann.response_b and ann.response_b.strip():
                resp_b = ann.response_b.strip()

    return resp_a, resp_b, rationales


def _compute_rubric_means(annotations: Sequence["TaskAnnotation"]) -> dict[str, float]:
    means: dict[str, float] = {}
    for metric in ("overall", "helpfulness", "harmlessness", "honesty"):
        vals = [
            float(v)
            for ann in annotations
            if isinstance(ann.rubric_scores, dict)
            and isinstance((v := ann.rubric_scores.get(metric)), (int, float))
        ]
        if vals:
            means[metric] = round(sum(vals) / len(vals), 2)
    return means


def build_dpo_export_record(
    task_obj: "Task",
    *,
    lang: str = "en",
    min_consensus_score: float = 0.50,
    include_ties: bool = False,
    redact_pii: bool = True,
    eval_ratio: float = 0.10,
    split_seed: str = "v1",
    schema_style: str = "trl",
    cal_map: Mapping[Any, "AnnotatorCalibration"] | None = None,
) -> tuple[dict[str, Any] | None, int]:
    """Build a single quality-gated DPO/RLHF record and return ``(record_or_None, pii_count)``."""
    choice = str(task_obj.consensus_choice or "").strip()
    valid_choices = (
        {"response_a", "response_b", "tie"} if include_ties else {"response_a", "response_b"}
    )
    if choice not in valid_choices:
        return None, 0

    if task_obj.consensus_score is not None and float(task_obj.consensus_score) < float(
        min_consensus_score
    ):
        return None, 0

    annotations = list(task_obj.annotations.all())
    resp_a, resp_b, rationales = _extract_candidate_pair(annotations, choice)
    if not resp_a or not resp_b:
        return None, 0

    title = (
        task_obj.safe_translation_getter("title", language_code=lang, any_language=True) or ""
    ).strip()
    desc = (
        task_obj.safe_translation_getter("description", language_code=lang, any_language=True) or ""
    ).strip()
    raw_prompt = f"{title}\n\n{desc}".strip() if (title and desc) else (desc or title)
    if not raw_prompt:
        return None, 0

    if choice == "response_b":
        chosen_raw, rejected_raw = resp_b, resp_a
    else:
        chosen_raw, rejected_raw = resp_a, resp_b

    redactions = 0
    if redact_pii:
        prompt_out, c_p = scrub_dataset_pii(raw_prompt)
        chosen_out, c_c = scrub_dataset_pii(chosen_raw)
        rejected_out, c_r = scrub_dataset_pii(rejected_raw)
        scrubbed_rationales: list[str] = []
        for rat in rationales:
            s_rat, c_rat = scrub_dataset_pii(rat)
            scrubbed_rationales.append(s_rat)
            redactions += c_rat
        redactions += c_p + c_c + c_r
    else:
        prompt_out = raw_prompt
        chosen_out = chosen_raw
        rejected_out = rejected_raw
        scrubbed_rationales = rationales

    cal_lookup = cal_map or {}
    task_domain = str(task_obj.domain or "general").strip().lower()
    winner_weights = [
        resolve_effective_skill_weight(
            cal_lookup.get(ann.annotator_id),
            domain=task_domain,
            language=lang,
        )
        for ann in annotations
        if ann.preference == choice
    ]
    mean_skill_weight = (
        round(sum(winner_weights) / len(winner_weights), 4) if winner_weights else 1.0
    )

    split_name = assign_deterministic_split(
        str(task_obj.id),
        eval_ratio=eval_ratio,
        split_seed=split_seed,
    )
    canonical_row = {
        "id": str(task_obj.id),
        "split": split_name,
        "language": lang,
        "domain": task_domain,
        "prompt": prompt_out,
        "chosen": chosen_out,
        "rejected": rejected_out,
        "winning_choice": choice,
    }
    row_sha256 = hashlib.sha256(
        json.dumps(
            canonical_row,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()

    record: dict[str, Any] = {
        "id": str(task_obj.id),
        "split": split_name,
        "language": lang,
        "domain": task_domain,
        "difficulty": task_obj.difficulty,
        "prompt": prompt_out,
        "chosen": chosen_out,
        "rejected": rejected_out,
        "winning_choice": choice,
        "consensus_score": task_obj.consensus_score,
        "uncertainty_score": task_obj.uncertainty_score,
        "judge_uncertainty_score": task_obj.judge_uncertainty_score,
        "auto_escalated": bool(task_obj.auto_escalated),
        "winning_skill_weight": mean_skill_weight,
        "annotation_count": len(annotations),
        "rubric_means": _compute_rubric_means(annotations),
        "rationales": scrubbed_rationales,
        "pii_redactions": redactions,
        "row_sha256": row_sha256,
    }
    if schema_style == "chat":
        record["chosen_messages"] = [
            {"role": "user", "content": prompt_out},
            {"role": "assistant", "content": chosen_out},
        ]
        record["rejected_messages"] = [
            {"role": "user", "content": prompt_out},
            {"role": "assistant", "content": rejected_out},
        ]

    return record, redactions


def compute_canonical_dpo_manifest_hash(manifest_core: Mapping[str, Any]) -> str:
    """Compute deterministic SHA-256 hex digest over canonical provenance manifest fields."""
    envelope = {
        "schema_version": str(manifest_core["schema_version"]),
        "organization_id": manifest_core.get("organization_id"),
        "language": str(manifest_core["language"]),
        "split_seed": str(manifest_core["split_seed"]),
        "eval_ratio": round(float(manifest_core["eval_ratio"]), 4),
        "min_consensus_score": round(float(manifest_core["min_consensus_score"]), 4),
        "redact_pii": bool(manifest_core["redact_pii"]),
        "total_records": int(manifest_core["total_records"]),
        "train_records": int(manifest_core["train_records"]),
        "eval_records": int(manifest_core["eval_records"]),
        "pii_redactions_total": int(manifest_core["pii_redactions_total"]),
        "dataset_sha256": str(manifest_core["dataset_sha256"]),
        "merkle_root": str(manifest_core["merkle_root"]),
        "exported_at": _canonical_timestamp(manifest_core["exported_at"]),
    }
    encoded = json.dumps(
        envelope,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def verify_dpo_manifest_offline(
    manifest_data: Mapping[str, Any],
    public_key_pem: str,
) -> dict[str, Any]:
    """Verify a signed DPO dataset provenance manifest offline using ONLY ``public_key_pem``."""
    recomputed_hash = compute_canonical_dpo_manifest_hash(manifest_data)
    reasons: list[str] = []
    claimed_hash = str(manifest_data.get("manifest_hash") or "")
    if not claimed_hash or not hmac.compare_digest(claimed_hash, recomputed_hash):
        reasons.append("manifest_hash_mismatch")

    pub_key = serialization.load_pem_public_key(_normalize_pem_bytes(public_key_pem))
    _pem, actual_fp = _spki_pem_and_fingerprint(pub_key)
    sig_alg = str(manifest_data.get("signature_algorithm") or "HMAC-SHA256")
    asym_sig = str(manifest_data.get("asymmetric_signature") or "")
    expected_fp = str(manifest_data.get("public_key_fingerprint") or "")

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
        "recomputed_manifest_hash": recomputed_hash,
        "public_key_fingerprint": actual_fp,
        "signature_algorithm": sig_alg,
        "reasons": reasons,
    }


def upload_dataset_snapshot_to_s3(
    *,
    bucket: str,
    region: str,
    object_key: str,
    payload_bytes: bytes,
    content_type: str = "application/json",
    endpoint_host: str = "",
) -> dict[str, str]:
    """Upload a signed DPO dataset snapshot to S3 via zero-dependency AWS SigV4 HTTPS PUT."""
    access_key = os.getenv("AWS_ACCESS_KEY_ID", "").strip()
    secret_key = os.getenv("AWS_SECRET_ACCESS_KEY", "").strip()
    session_token = os.getenv("AWS_SESSION_TOKEN", "").strip()
    if not access_key or not secret_key:
        raise RuntimeError(
            "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are required for S3 dataset export."
        )

    now_utc = datetime.now(dt_timezone.utc)
    amz_date = now_utc.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now_utc.strftime("%Y%m%d")
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
        "content-type": content_type,
        "host": host,
        "x-amz-content-sha256": payload_sha256,
        "x-amz-date": amz_date,
        "x-amz-server-side-encryption": "AES256",
    }
    if session_token:
        signed_headers_map["x-amz-security-token"] = session_token

    sorted_keys = sorted(signed_headers_map.keys())
    canonical_headers = "".join(f"{k}:{signed_headers_map[k]}\n" for k in sorted_keys)
    signed_headers_str = ";".join(sorted_keys)
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
        "Content-Type": content_type,
        "x-amz-content-sha256": payload_sha256,
        "x-amz-date": amz_date,
        "x-amz-server-side-encryption": "AES256",
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
            raise RuntimeError(
                f"S3 dataset export PUT failed with HTTP {resp.status}: {resp_body[:300]}"
            )
        etag = (resp.getheader("ETag") or "").strip('"')
        return {
            "s3_uri": f"s3://{bucket}/{object_key.lstrip('/')}",
            "etag": etag,
        }
    finally:
        conn.close()


def build_signed_dpo_manifest(
    records: Sequence[dict[str, Any]],
    *,
    organization_id: str | None,
    lang: str,
    split_seed: str,
    eval_ratio: float,
    min_consensus_score: float,
    redact_pii: bool,
    pii_redactions_total: int,
) -> dict[str, Any]:
    """Build an RFC 9162 Merkle-rooted, HMAC + Ed25519/KMS signed dataset provenance manifest."""
    ndjson_bytes = "".join(
        json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
        for row in records
    ).encode("utf-8")
    dataset_sha256 = hashlib.sha256(ndjson_bytes).hexdigest()
    row_hashes = [str(row["row_sha256"]) for row in records]
    merkle_root = compute_merkle_root(row_hashes)

    train_count = sum(1 for r in records if r["split"] == "train")
    eval_count = sum(1 for r in records if r["split"] == "eval")
    by_domain: dict[str, int] = {}
    for row in records:
        dom = str(row["domain"])
        by_domain[dom] = by_domain.get(dom, 0) + 1

    exported_at = _canonical_timestamp(timezone.now())
    manifest_core: dict[str, Any] = {
        "schema_version": "dpo-export/v1.0",
        "organization_id": organization_id,
        "language": lang,
        "split_seed": split_seed,
        "eval_ratio": round(float(eval_ratio), 4),
        "min_consensus_score": round(float(min_consensus_score), 4),
        "redact_pii": bool(redact_pii),
        "total_records": len(records),
        "train_records": train_count,
        "eval_records": eval_count,
        "by_domain": by_domain,
        "pii_redactions_total": int(pii_redactions_total),
        "dataset_sha256": dataset_sha256,
        "merkle_root": merkle_root,
        "exported_at": exported_at,
    }
    manifest_hash = compute_canonical_dpo_manifest_hash(manifest_core)
    hmac_sig = hmac.new(
        _anchor_signing_secret(),
        manifest_hash.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()

    sig_alg = "HMAC-SHA256"
    pub_fp = ""
    asym_sig = ""
    try:
        sig_alg, pub_fp, asym_sig = sign_checkpoint_asymmetrically(manifest_hash)
    except Exception:
        sig_alg = "HMAC-SHA256"

    return {
        **manifest_core,
        "manifest_hash": manifest_hash,
        "signature": hmac_sig,
        "signature_algorithm": sig_alg,
        "public_key_fingerprint": pub_fp,
        "asymmetric_signature": asym_sig,
    }
