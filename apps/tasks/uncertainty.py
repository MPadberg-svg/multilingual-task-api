"""Active-learning preference uncertainty & adaptive per-domain threshold calibration.

Combines normalized 3-class Shannon entropy over ``("response_a", "response_b", "tie")``
with least-margin uncertainty ``1 - (p_1 - p_2)`` so both deadlocked binary A/B splits
(``0.50 / 0.50 / 0.00`` -> ``0.8155``) and 3-way splits (``0.34 / 0.33 / 0.33`` -> ``0.9949``)
exceed the default escalation threshold while decisive winners (``0.92 / 0.05 / 0.03``
-> ``0.2170``) remain in standard annotation queues.

In ``v1.11.0``, ``DomainUncertaintyPolicy`` continuously calibrates escalation thresholds
per ``(organization, domain)`` from empirical correlation between LLM judge uncertainty
(``Task.judge_uncertainty_score``) and downstream human split-vote deadlocks.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.core.cache import cache
from django.db import transaction
from django.db.models import Count
from django.utils import timezone

from apps.core.db_router import use_read_replica
from apps.core.outbox import enqueue_outbox_event
from apps.core.rls import rls_bypass

if TYPE_CHECKING:
    from apps.core.models import Organization
    from apps.tasks.models import DomainUncertaintyPolicy

PREFERENCE_KEYS: tuple[str, str, str] = ("response_a", "response_b", "tie")
VALID_TASK_DOMAINS: tuple[str, ...] = (
    "general",
    "code",
    "math",
    "medical",
    "legal",
    "creative",
    "safety",
)
MIN_ADAPTIVE_THRESHOLD: float = 0.45
MAX_ADAPTIVE_THRESHOLD: float = 0.92
_POLICY_CACHE_TTL_SECONDS: int = 300
_DEFAULT_SENTINEL: str = "__default__"
_LOG_3: float = math.log(3.0)


def _policy_cache_key(organization_id: str, domain: str) -> str:
    return f"mltask:unc_policy:{organization_id}:{domain}"


def invalidate_domain_threshold_cache(
    organization_id: str,
    domain: str | None = None,
) -> None:
    """Evict cached adaptive uncertainty threshold(s) for ``organization_id``."""
    if not organization_id:
        return
    if domain:
        cache.delete(_policy_cache_key(organization_id, domain.strip().lower()))
        return
    cache.delete_many([_policy_cache_key(organization_id, d) for d in VALID_TASK_DOMAINS])


def get_active_learning_entropy_threshold() -> float:
    """Return configured global active-learning uncertainty threshold in ``(0, 1]``."""
    raw = float(getattr(settings, "ACTIVE_LEARNING_ENTROPY_THRESHOLD", 0.78))
    return min(1.0, max(0.05, raw))


def resolve_domain_entropy_threshold(
    organization_id: str | None = None,
    domain: str = "general",
) -> float:
    """Resolve effective active-learning threshold for ``(organization_id, domain)``."""
    default_threshold = get_active_learning_entropy_threshold()
    org_id_clean = str(organization_id or "").strip()
    if not org_id_clean:
        return default_threshold

    clean_domain = str(domain or "general").strip().lower()
    if clean_domain not in VALID_TASK_DOMAINS:
        clean_domain = "general"

    cache_key = _policy_cache_key(org_id_clean, clean_domain)
    cached = cache.get(cache_key)
    if cached == _DEFAULT_SENTINEL:
        return default_threshold
    if isinstance(cached, (int, float)):
        return float(cached)

    from apps.tasks.models import DomainUncertaintyPolicy

    policy_val = (
        DomainUncertaintyPolicy.objects.filter(
            organization_id=org_id_clean,
            domain=clean_domain,
        )
        .values_list("threshold", flat=True)
        .first()
    )
    if policy_val is None:
        cache.set(cache_key, _DEFAULT_SENTINEL, timeout=_POLICY_CACHE_TTL_SECONDS)
        return default_threshold

    resolved = round(min(1.0, max(0.05, float(policy_val))), 4)
    cache.set(cache_key, resolved, timeout=_POLICY_CACHE_TTL_SECONDS)
    return resolved


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


def compute_preference_uncertainty(
    weights: Mapping[str, Any],
    *,
    threshold: float | None = None,
    organization_id: str | None = None,
    domain: str = "general",
) -> dict[str, Any]:
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
    effective_threshold = (
        round(min(1.0, max(0.05, float(threshold))), 4)
        if threshold is not None
        else resolve_domain_entropy_threshold(organization_id=organization_id, domain=domain)
    )

    return {
        "normalized_probabilities": probs,
        "shannon_entropy": shannon_entropy,
        "margin_uncertainty": margin_uncertainty,
        "uncertainty_score": uncertainty_score,
        "threshold": effective_threshold,
        "should_escalate": uncertainty_score >= effective_threshold,
    }


def upsert_domain_uncertainty_policy(
    org: "Organization",
    *,
    domain: str,
    threshold: float | None = None,
    auto_calibrate: bool | None = None,
) -> "DomainUncertaintyPolicy":
    """Create or update a pinned or adaptive ``DomainUncertaintyPolicy`` for ``(org, domain)``."""
    from apps.tasks.models import DomainUncertaintyPolicy

    clean_domain = str(domain or "general").strip().lower()
    if clean_domain not in VALID_TASK_DOMAINS:
        raise ValueError(f"Unsupported domain '{domain}'.")

    default_t = get_active_learning_entropy_threshold()
    with transaction.atomic():
        policy, _created = DomainUncertaintyPolicy.objects.select_for_update().get_or_create(
            organization=org,
            domain=clean_domain,
            defaults={
                "threshold": (
                    round(min(0.99, max(0.10, float(threshold))), 4)
                    if threshold is not None
                    else default_t
                ),
                "auto_calibrate": True if auto_calibrate is None else bool(auto_calibrate),
            },
        )
        update_fields = ["updated_at"]
        if threshold is not None:
            policy.threshold = round(min(0.99, max(0.10, float(threshold))), 4)
            update_fields.append("threshold")
        if auto_calibrate is not None:
            policy.auto_calibrate = bool(auto_calibrate)
            update_fields.append("auto_calibrate")
        if len(update_fields) > 1:
            policy.save(update_fields=update_fields)

    invalidate_domain_threshold_cache(str(org.id), clean_domain)
    return policy


def calibrate_organization_domain_thresholds(
    org: "Organization",
    *,
    min_samples: int = 3,
    target_domain: str | None = None,
) -> dict[str, Any]:
    """Calibrate per-domain uncertainty thresholds from empirical LLM-judge vs split-vote rates."""
    from apps.tasks.models import DomainUncertaintyPolicy, Task

    min_req = max(1, int(min_samples))
    default_threshold = get_active_learning_entropy_threshold()
    now_utc = timezone.now()

    scoped_tasks = Task.objects.filter(
        organization_id=org.id, is_active=True, is_gold=False
    ).annotate(ann_total=Count("annotations"))
    if target_domain:
        clean_target = target_domain.strip().lower()
        scoped_tasks = scoped_tasks.filter(domain=clean_target)
        domains_to_scan = [clean_target] if clean_target in VALID_TASK_DOMAINS else []
    else:
        domains_to_scan = list(VALID_TASK_DOMAINS)

    tasks_by_domain: dict[str, list[Task]] = {d: [] for d in domains_to_scan}
    for task_item in scoped_tasks:
        dom = str(task_item.domain or "general")
        if dom in tasks_by_domain:
            tasks_by_domain[dom].append(task_item)

    existing_policies = {
        p.domain: p for p in DomainUncertaintyPolicy.objects.filter(organization_id=org.id)
    }

    adjusted_domains: list[dict[str, Any]] = []
    evaluated_domains = 0

    with transaction.atomic():
        for dom in domains_to_scan:
            dom_tasks = tasks_by_domain.get(dom, [])
            existing = existing_policies.get(dom)
            if not dom_tasks and existing is None:
                continue

            evaluated_domains += 1
            current_threshold = (
                float(existing.threshold) if existing is not None else default_threshold
            )
            auto_cal = True if existing is None else bool(existing.auto_calibrate)

            triaged_tasks = [t for t in dom_tasks if t.judge_uncertainty_score is not None]
            resolved_tasks: list[Task] = []
            split_tasks: list[Task] = []
            unpredicted_splits = 0
            false_escalations = 0

            for t in dom_tasks:
                ann_total = int(getattr(t, "ann_total", 0) or 0)
                has_reached_quorum = ann_total >= int(t.required_annotations)
                is_resolved = bool(t.consensus_choice) or has_reached_quorum
                if not is_resolved:
                    continue
                resolved_tasks.append(t)

                is_split = t.consensus_choice in ("", "needs_review", "tie") or (
                    t.consensus_score is not None and float(t.consensus_score) <= 0.5001
                )
                if is_split:
                    split_tasks.append(t)
                    if (
                        t.judge_uncertainty_score is not None
                        and float(t.judge_uncertainty_score) < current_threshold
                    ):
                        unpredicted_splits += 1
                elif (
                    t.judge_uncertainty_score is not None
                    and float(t.judge_uncertainty_score) >= current_threshold
                    and t.consensus_choice in ("response_a", "response_b")
                    and float(t.consensus_score or 0.0) >= 0.95
                ):
                    false_escalations += 1

            resolved_count = len(resolved_tasks)
            split_count = len(split_tasks)
            triaged_count = len(triaged_tasks)
            split_rate = round(split_count / resolved_count, 4) if resolved_count > 0 else 0.0

            new_threshold = current_threshold
            if auto_cal and resolved_count >= min_req:
                if unpredicted_splits > 0 or split_rate >= 0.35:
                    split_judge_scores = sorted(
                        float(t.judge_uncertainty_score)
                        for t in split_tasks
                        if t.judge_uncertainty_score is not None
                    )
                    if split_judge_scores:
                        q25_idx = max(0, int(0.25 * (len(split_judge_scores) - 1)))
                        anchor_target = max(
                            MIN_ADAPTIVE_THRESHOLD, split_judge_scores[q25_idx] - 0.02
                        )
                    else:
                        anchor_target = max(
                            MIN_ADAPTIVE_THRESHOLD,
                            current_threshold - 0.08 * (1.0 + split_rate),
                        )
                    damped = 0.50 * current_threshold + 0.50 * anchor_target
                    stepped = min(current_threshold - 0.03, damped)
                    new_threshold = round(
                        min(MAX_ADAPTIVE_THRESHOLD, max(MIN_ADAPTIVE_THRESHOLD, stepped)),
                        4,
                    )
                elif (
                    unpredicted_splits == 0
                    and split_rate <= 0.10
                    and (
                        false_escalations >= 2
                        or (
                            triaged_count >= min_req
                            and (false_escalations / max(1, triaged_count)) >= 0.50
                        )
                    )
                ):
                    new_threshold = round(
                        min(MAX_ADAPTIVE_THRESHOLD, current_threshold + 0.05),
                        4,
                    )

            policy_obj, _ = DomainUncertaintyPolicy.objects.update_or_create(
                organization=org,
                domain=dom,
                defaults={
                    "threshold": new_threshold,
                    "auto_calibrate": auto_cal,
                    "triaged_count": triaged_count,
                    "resolved_count": resolved_count,
                    "split_vote_count": split_count,
                    "unpredicted_split_count": unpredicted_splits,
                    "false_escalation_count": false_escalations,
                    "empirical_split_rate": split_rate,
                    "last_calibrated_at": now_utc,
                },
            )
            if abs(new_threshold - current_threshold) >= 0.005:
                adjusted_domains.append(
                    {
                        "domain": dom,
                        "previous_threshold": round(current_threshold, 4),
                        "new_threshold": float(policy_obj.threshold),
                        "empirical_split_rate": split_rate,
                        "unpredicted_split_count": unpredicted_splits,
                        "false_escalation_count": false_escalations,
                    }
                )

        if adjusted_domains:
            enqueue_outbox_event(
                organization_id=str(org.id),
                event_type="uncertainty.policy_calibrated",
                payload={
                    "organization_id": str(org.id),
                    "adjusted_domains": adjusted_domains,
                    "calibrated_at": now_utc.isoformat(),
                },
            )

    invalidate_domain_threshold_cache(str(org.id))
    return {
        "organization_id": str(org.id),
        "evaluated_domains": evaluated_domains,
        "adjusted_count": len(adjusted_domains),
        "adjusted_domains": adjusted_domains,
    }


def get_organization_uncertainty_policies(
    org: "Organization",
) -> tuple[dict[str, Any], str]:
    """Replica-routed summary of per-domain uncertainty thresholds & empirical split metrics."""
    from apps.tasks.models import DomainUncertaintyPolicy

    default_threshold = get_active_learning_entropy_threshold()
    with use_read_replica() as query_target:
        rows = list(
            DomainUncertaintyPolicy.objects.filter(organization_id=org.id).order_by("domain")
        )

    by_domain = {r.domain: r for r in rows}
    policies_out: list[dict[str, Any]] = []
    for dom in VALID_TASK_DOMAINS:
        row = by_domain.get(dom)
        if row is not None:
            policies_out.append(
                {
                    "domain": dom,
                    "threshold": round(float(row.threshold), 4),
                    "source": "adaptive" if row.auto_calibrate else "pinned",
                    "auto_calibrate": bool(row.auto_calibrate),
                    "triaged_count": int(row.triaged_count),
                    "resolved_count": int(row.resolved_count),
                    "split_vote_count": int(row.split_vote_count),
                    "unpredicted_split_count": int(row.unpredicted_split_count),
                    "false_escalation_count": int(row.false_escalation_count),
                    "empirical_split_rate": round(float(row.empirical_split_rate), 4),
                    "last_calibrated_at": (
                        row.last_calibrated_at.isoformat() if row.last_calibrated_at else None
                    ),
                }
            )
        else:
            policies_out.append(
                {
                    "domain": dom,
                    "threshold": default_threshold,
                    "source": "global_default",
                    "auto_calibrate": True,
                    "triaged_count": 0,
                    "resolved_count": 0,
                    "split_vote_count": 0,
                    "unpredicted_split_count": 0,
                    "false_escalation_count": 0,
                    "empirical_split_rate": 0.0,
                    "last_calibrated_at": None,
                }
            )

    return (
        {
            "organization_id": str(org.id),
            "global_default_threshold": default_threshold,
            "policies": policies_out,
            "query_target": query_target,
        },
        query_target,
    )


def calibrate_all_organizations_thresholds(
    *,
    min_samples: int = 3,
    batch_size: int = 100,
) -> dict[str, int]:
    """Periodic Celery Beat Sweep calibrating per-domain uncertainty thresholds across tenants."""
    from apps.core.models import Organization

    calibrated_orgs = 0
    adjusted_total = 0
    with rls_bypass():
        orgs = list(
            Organization.objects.filter(is_active=True, tasks__isnull=False)
            .distinct()
            .order_by("created_at")[: max(1, int(batch_size))]
        )

    for org in orgs:
        with rls_bypass():
            summary = calibrate_organization_domain_thresholds(org, min_samples=min_samples)
            calibrated_orgs += 1
            adjusted_total += int(summary["adjusted_count"])

    return {
        "organizations_evaluated": calibrated_orgs,
        "domains_adjusted": adjusted_total,
    }
