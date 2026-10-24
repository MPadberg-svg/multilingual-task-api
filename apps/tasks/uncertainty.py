"""Active-learning preference uncertainty & Shannon/margin entropy scoring for RLHF tasks.

Combines normalized 3-class Shannon entropy over ``("response_a", "response_b", "tie")``
with least-margin uncertainty ``1 - (p_1 - p_2)`` so both deadlocked binary A/B splits
(``0.50 / 0.50 / 0.00`` -> ``0.8155``) and 3-way splits (``0.34 / 0.33 / 0.33`` -> ``0.9949``)
exceed the active-learning escalation threshold while decisive winners (``0.92 / 0.05 / 0.03``
-> ``0.2170``) remain in standard annotation queues.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any

from django.conf import settings

PREFERENCE_KEYS: tuple[str, str, str] = ("response_a", "response_b", "tie")
_LOG_3: float = math.log(3.0)


def get_active_learning_entropy_threshold() -> float:
    """Return configured active-learning uncertainty escalation threshold in ``(0, 1]``."""
    raw = float(getattr(settings, "ACTIVE_LEARNING_ENTROPY_THRESHOLD", 0.78))
    return min(1.0, max(0.05, raw))


def normalize_choice_distribution(weights: Mapping[str, Any]) -> dict[str, float]:
    """Normalize non-negative preference scores over ``response_a``, ``response_b``, ``tie``."""
    raw_map: dict[str, float] = {}
    for key in PREFERENCE_KEYS:
        val = weights.get(key, 0.0)
        raw_map[key] = max(0.0, float(val)) if isinstance(val, (int, float)) else 0.0

    total = sum(raw_map.values())
    if total <= 0.0:
        uniform = round(1.0 / 3.0, 6)
        return {"response_a": uniform, "response_b": uniform, "tie": round(1.0 - 2 * uniform, 6)}

    probs = {k: raw_map[k] / total for k in PREFERENCE_KEYS}
    rounded_a = round(probs["response_a"], 6)
    rounded_b = round(probs["response_b"], 6)
    rounded_tie = round(max(0.0, 1.0 - rounded_a - rounded_b), 6)
    return {
        "response_a": rounded_a,
        "response_b": rounded_b,
        "tie": rounded_tie,
    }


def compute_preference_uncertainty(weights: Mapping[str, Any]) -> dict[str, Any]:
    """Return normalized distribution, Shannon entropy, margin uncertainty & hybrid score."""
    probs = normalize_choice_distribution(weights)
    ordered = sorted(probs.values(), reverse=True)

    raw_entropy = 0.0
    for p_val in ordered:
        if p_val > 0.0:
            raw_entropy -= p_val * math.log(p_val)

    shannon_entropy = round(min(1.0, max(0.0, raw_entropy / _LOG_3)), 4)
    margin = max(0.0, ordered[0] - ordered[1])
    margin_uncertainty = round(min(1.0, max(0.0, 1.0 - margin)), 4)
    uncertainty_score = round(0.5 * shannon_entropy + 0.5 * margin_uncertainty, 4)
    threshold = get_active_learning_entropy_threshold()

    return {
        "normalized_probabilities": probs,
        "shannon_entropy": shannon_entropy,
        "margin_uncertainty": margin_uncertainty,
        "uncertainty_score": uncertainty_score,
        "threshold": threshold,
        "should_escalate": uncertainty_score >= threshold,
    }
