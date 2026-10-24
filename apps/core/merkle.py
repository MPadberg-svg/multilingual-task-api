"""RFC 9162 §2.1 binary Merkle transparency tree, inclusion proofs & consistency proofs.

Implements domain-separated SHA-256 Merkle Tree Hashing (``MTH``), $O(\\log N)$ audit
inclusion paths (``PATH``), and append-only consistency proofs (``PROOF`` / ``SUBPROOF``)
over ``AuditLog.entry_hash`` sequences and exported RLHF/DPO dataset rows:

    - Empty tree: ``MTH({}) = SHA-256(b"")``
    - Leaf node:  ``MTH({d(0)}) = SHA-256(0x00 || d(0))``
    - Interior:   ``MTH(D[0..n)) = SHA-256(0x01 || MTH(D[0..k)) || MTH(D[k..n)))``
      where ``k`` is the largest power of two strictly less than ``n``.

Domain-separation prefixes ``0x00`` (leaf) and ``0x01`` (interior node) prevent
second-preimage attacks conflating leaf payloads with interior subtree hashes.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Sequence
from typing import Any

EMPTY_MERKLE_ROOT: str = hashlib.sha256(b"").hexdigest()
_LEAF_PREFIX: bytes = b"\x00"
_NODE_PREFIX: bytes = b"\x01"


def _decode_digest_hex(hex_digest: str) -> bytes:
    cleaned = str(hex_digest or "").strip().lower()
    if len(cleaned) != 64:
        raise ValueError("Expected a 64-character hexadecimal SHA-256 digest.")
    return bytes.fromhex(cleaned)


def hash_merkle_leaf(leaf_hex: str) -> str:
    """Compute RFC 9162 §2.1 leaf hash ``SHA-256(0x00 || bytes.fromhex(leaf_hex))``."""
    raw = _decode_digest_hex(leaf_hex)
    return hashlib.sha256(_LEAF_PREFIX + raw).hexdigest()


def hash_merkle_children(left_hex: str, right_hex: str) -> str:
    """Compute RFC 9162 §2.1 interior node hash ``SHA-256(0x01 || left || right)``."""
    left_raw = _decode_digest_hex(left_hex)
    right_raw = _decode_digest_hex(right_hex)
    return hashlib.sha256(_NODE_PREFIX + left_raw + right_raw).hexdigest()


def _largest_power_of_two_less_than(n: int) -> int:
    """Return the largest power of 2 strictly less than ``n`` (requires ``n >= 2``)."""
    if n < 2:
        raise ValueError("n must be >= 2 to split an interior Merkle node.")
    return 1 << ((n - 1).bit_length() - 1)


def compute_merkle_root(leaf_hex_digests: Sequence[str]) -> str:
    """Compute RFC 9162 §2.1.1 ``MTH(D[0..n))`` over 64-char SHA-256 leaf hex digests."""
    count = len(leaf_hex_digests)
    if count == 0:
        return EMPTY_MERKLE_ROOT
    if count == 1:
        return hash_merkle_leaf(leaf_hex_digests[0])
    split = _largest_power_of_two_less_than(count)
    left_root = compute_merkle_root(leaf_hex_digests[:split])
    right_root = compute_merkle_root(leaf_hex_digests[split:])
    return hash_merkle_children(left_root, right_root)


def build_merkle_inclusion_proof(
    leaf_hex_digests: Sequence[str],
    leaf_index: int,
) -> list[str]:
    """Compute RFC 9162 §2.1.3 ``PATH(m, D[0..n))`` ordered leaf-to-root in $O(\\log N)$."""
    count = len(leaf_hex_digests)
    if count == 0 or leaf_index < 0 or leaf_index >= count:
        raise ValueError(f"Leaf index {leaf_index} out of bounds for tree of size {count}.")
    if count == 1:
        return []

    split = _largest_power_of_two_less_than(count)
    if leaf_index < split:
        sub_path = build_merkle_inclusion_proof(leaf_hex_digests[:split], leaf_index)
        sibling = compute_merkle_root(leaf_hex_digests[split:])
        return [*sub_path, sibling]

    sub_path = build_merkle_inclusion_proof(leaf_hex_digests[split:], leaf_index - split)
    sibling = compute_merkle_root(leaf_hex_digests[:split])
    return [*sub_path, sibling]


def verify_merkle_inclusion_path(
    *,
    leaf_hex: str,
    leaf_index: int,
    tree_size: int,
    audit_path: Sequence[str],
    expected_root: str,
) -> dict[str, Any]:
    """Verify an RFC 9162 §2.1.3.2 inclusion proof against ``expected_root``."""
    reasons: list[str] = []
    if tree_size <= 0 or leaf_index < 0 or leaf_index >= tree_size:
        return {
            "valid": False,
            "recomputed_root": "",
            "leaf_hash": "",
            "reasons": ["invalid_tree_bounds"],
        }

    try:
        leaf_hash = hash_merkle_leaf(leaf_hex)
    except ValueError:
        return {
            "valid": False,
            "recomputed_root": "",
            "leaf_hash": "",
            "reasons": ["malformed_leaf_digest"],
        }

    fn = int(leaf_index)
    sn = int(tree_size) - 1
    running = leaf_hash

    try:
        for sibling_hex in audit_path:
            if sn == 0:
                reasons.append("audit_path_length_mismatch")
                break
            if (fn & 1) == 1 or fn == sn:
                running = hash_merkle_children(sibling_hex, running)
                while (fn & 1) == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
            else:
                running = hash_merkle_children(running, sibling_hex)
            fn >>= 1
            sn >>= 1
    except ValueError:
        reasons.append("malformed_audit_path_digest")

    if sn != 0 and "audit_path_length_mismatch" not in reasons:
        reasons.append("audit_path_length_mismatch")

    expected_clean = str(expected_root or "").strip().lower()
    if not expected_clean or not hmac.compare_digest(running, expected_clean):
        reasons.append("merkle_root_mismatch")

    return {
        "valid": len(reasons) == 0,
        "recomputed_root": running,
        "leaf_hash": leaf_hash,
        "reasons": reasons,
    }


def _subproof(
    leaf_hex_digests: Sequence[str],
    first_size: int,
    start_from_old_root: bool,
) -> list[str]:
    """RFC 9162 §2.1.4 ``SUBPROOF(m, D[0..n), b)`` helper."""
    total = len(leaf_hex_digests)
    if first_size == total:
        return [] if start_from_old_root else [compute_merkle_root(leaf_hex_digests)]

    split = _largest_power_of_two_less_than(total)
    if first_size <= split:
        sub = _subproof(leaf_hex_digests[:split], first_size, start_from_old_root)
        right_root = compute_merkle_root(leaf_hex_digests[split:])
        return [*sub, right_root]

    sub = _subproof(leaf_hex_digests[split:], first_size - split, False)
    left_root = compute_merkle_root(leaf_hex_digests[:split])
    return [*sub, left_root]


def build_merkle_consistency_proof(
    leaf_hex_digests: Sequence[str],
    first_size: int,
) -> list[str]:
    """Compute RFC 9162 §2.1.4 ``PROOF(m, D[0..n))`` proving append-only prefix consistency."""
    second_size = len(leaf_hex_digests)
    if first_size < 0 or first_size > second_size:
        raise ValueError(
            f"Invalid consistency bounds: first_size={first_size}, second_size={second_size}."
        )
    if first_size == 0 or first_size == second_size:
        return []
    return _subproof(leaf_hex_digests, first_size, True)


def verify_merkle_consistency_proof(
    *,
    first_size: int,
    second_size: int,
    first_root: str,
    second_root: str,
    consistency_path: Sequence[str],
) -> dict[str, Any]:
    """Verify RFC 9162 §2.1.4.2 append-only consistency between two Merkle roots."""
    first_clean = str(first_root or "").strip().lower()
    second_clean = str(second_root or "").strip().lower()

    if first_size < 0 or second_size < 0 or first_size > second_size:
        return {"valid": False, "reasons": ["invalid_consistency_bounds"]}

    if first_size == 0:
        valid_empty = (
            hmac.compare_digest(first_clean, EMPTY_MERKLE_ROOT) and len(consistency_path) == 0
        )
        return {
            "valid": valid_empty,
            "reasons": [] if valid_empty else ["consistency_root_mismatch"],
        }

    if first_size == second_size:
        same = hmac.compare_digest(first_clean, second_clean) and len(consistency_path) == 0
        return {
            "valid": same,
            "reasons": [] if same else ["consistency_root_mismatch"],
        }

    if len(consistency_path) == 0:
        return {"valid": False, "reasons": ["consistency_path_empty"]}

    is_exact_power_of_two = (first_size & (first_size - 1)) == 0
    path_nodes = (
        [first_clean, *consistency_path] if is_exact_power_of_two else list(consistency_path)
    )

    fn = first_size - 1
    sn = second_size - 1
    while (fn & 1) == 1:
        fn >>= 1
        sn >>= 1

    try:
        fr = path_nodes[0].strip().lower()
        sr = path_nodes[0].strip().lower()
        _decode_digest_hex(fr)
        for c_hex in path_nodes[1:]:
            if sn == 0:
                return {"valid": False, "reasons": ["consistency_path_length_mismatch"]}
            if (fn & 1) == 1 or fn == sn:
                fr = hash_merkle_children(c_hex, fr)
                sr = hash_merkle_children(c_hex, sr)
                while (fn & 1) == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
            else:
                sr = hash_merkle_children(sr, c_hex)
            fn >>= 1
            sn >>= 1
    except ValueError:
        return {"valid": False, "reasons": ["malformed_consistency_digest"]}

    reasons: list[str] = []
    if sn != 0:
        reasons.append("consistency_path_length_mismatch")
    if not hmac.compare_digest(fr, first_clean):
        reasons.append("first_root_mismatch")
    if not hmac.compare_digest(sr, second_clean):
        reasons.append("second_root_mismatch")

    return {
        "valid": len(reasons) == 0,
        "recomputed_first_root": fr,
        "recomputed_second_root": sr,
        "reasons": reasons,
    }
