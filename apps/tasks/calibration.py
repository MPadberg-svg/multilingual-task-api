"""Gold-standard annotator calibration, multi-dimensional skill vectors & specialist routing."""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING, Any

from django.utils import timezone

from apps.core.db_router import use_read_replica
from apps.core.models import OrganizationMember
from apps.core.outbox import enqueue_outbox_event
from apps.tasks.models import AnnotatorCalibration, Task, TaskAnnotation

if TYPE_CHECKING:
    from apps.core.models import Organization

CALIBRATION_SPOTCHECK_INTERVAL: int = 5
SPECIALIST_WEIGHT_THRESHOLD: float = 1.10
PROBATION_WEIGHT_CUTOFF: float = 0.70


def compute_bayesian_skill_weight(gold_correct: int, gold_evaluated: int) -> tuple[float, float]:
    """Compute empirical ``(accuracy_rate, skill_weight)`` using a Jeffreys Beta(0.5, 0.5) prior.

    Uncalibrated annotators (``gold_evaluated <= 0``) receive a neutral weight of ``1.0``.
    Calibrated annotators receive weights bounded in ``[0.10, 1.50]``:
        - ``1/1`` correct -> ``1.15``; ``4/4`` correct -> ``1.36``
        - ``0/1`` correct -> ``0.45``; ``0/4`` correct -> ``0.24``
    """
    if gold_evaluated <= 0:
        return 1.0, 1.0
    safe_correct = max(0, min(int(gold_correct), int(gold_evaluated)))
    accuracy_rate = round(safe_correct / int(gold_evaluated), 4)
    posterior_mean = (safe_correct + 0.5) / (int(gold_evaluated) + 1.0)
    skill_weight = round(max(0.10, min(1.50, 0.10 + 1.40 * posterior_mean)), 4)
    return accuracy_rate, skill_weight


def _update_dimension_vector(
    vectors_map: dict[str, Any],
    key: str,
    is_correct: bool,
) -> dict[str, Any]:
    updated = dict(vectors_map) if isinstance(vectors_map, dict) else {}
    norm_key = str(key or "").strip().lower()
    if not norm_key:
        return updated
    existing = updated.get(norm_key)
    prev_eval = int(existing.get("evaluated", 0)) if isinstance(existing, dict) else 0
    prev_corr = int(existing.get("correct", 0)) if isinstance(existing, dict) else 0
    new_eval = prev_eval + 1
    new_corr = prev_corr + (1 if is_correct else 0)
    acc, weight = compute_bayesian_skill_weight(new_corr, new_eval)
    updated[norm_key] = {
        "evaluated": new_eval,
        "correct": new_corr,
        "accuracy_rate": acc,
        "skill_weight": weight,
    }
    return updated


def resolve_effective_skill_weight(
    cal: AnnotatorCalibration | None,
    *,
    domain: str = "general",
    language: str = "en",
) -> float:
    """Resolve effective consensus weight blending specialist domain/language vectors with baseline."""
    if cal is None or int(cal.gold_evaluated_count) <= 0:
        return 1.0

    base_weight = float(cal.skill_weight)
    norm_domain = str(domain or "general").strip().lower()
    norm_lang = str(language or "en").strip().lower()

    matched_specialist_weights: list[float] = []
    if norm_domain != "general" and isinstance(cal.domain_skill_vectors, dict):
        d_vec = cal.domain_skill_vectors.get(norm_domain)
        if isinstance(d_vec, dict) and int(d_vec.get("evaluated", 0)) > 0:
            matched_specialist_weights.append(float(d_vec.get("skill_weight", base_weight)))

    if norm_lang != "en" and isinstance(cal.language_skill_vectors, dict):
        l_vec = cal.language_skill_vectors.get(norm_lang)
        if isinstance(l_vec, dict) and int(l_vec.get("evaluated", 0)) > 0:
            matched_specialist_weights.append(float(l_vec.get("skill_weight", base_weight)))

    if not matched_specialist_weights:
        return round(base_weight, 4)

    specialist_mean = sum(matched_specialist_weights) / len(matched_specialist_weights)
    blended = 0.70 * specialist_mean + 0.30 * base_weight
    return round(max(0.10, min(1.50, blended)), 4)


def get_annotator_claim_routing(
    organization: "Organization",
    user: Any,
) -> tuple[bool, bool, list[str]]:
    """Return ``(inject_gold_first, is_probation, trusted_specialist_domains)`` for ``claim()``."""
    cal = AnnotatorCalibration.objects.filter(organization=organization, user=user).first()
    if cal is None or int(cal.gold_evaluated_count) < 1:
        return True, False, []

    total_org_anns = TaskAnnotation.objects.filter(
        task__organization=organization,
        annotator=user,
    ).count()
    inject_gold = total_org_anns > 0 and (total_org_anns % CALIBRATION_SPOTCHECK_INTERVAL == 0)
    is_probation = float(cal.skill_weight) < PROBATION_WEIGHT_CUTOFF

    trusted_domains: list[str] = []
    if isinstance(cal.domain_skill_vectors, dict):
        for dom_key, vec in cal.domain_skill_vectors.items():
            if (
                dom_key != "general"
                and isinstance(vec, dict)
                and int(vec.get("evaluated", 0)) > 0
                and float(vec.get("skill_weight", 0.0)) >= SPECIALIST_WEIGHT_THRESHOLD
            ):
                trusted_domains.append(str(dom_key))

    return inject_gold, is_probation, sorted(trusted_domains)


def should_inject_gold_task(organization: "Organization", user: Any) -> bool:
    """Return True when ``claim()`` should prioritize an unannotated blind gold calibration task."""
    inject_gold, _probation, _domains = get_annotator_claim_routing(organization, user)
    return inject_gold


def evaluate_gold_annotation(
    task: Task,
    annotation: TaskAnnotation,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Score a blind gold-task submission, update global + specialist vectors & release lease."""
    is_correct = bool(task.gold_choice and annotation.preference == task.gold_choice)
    ann_lang = (
        str(annotation.rubric_scores.get("language") or "en").strip().lower()
        if isinstance(annotation.rubric_scores, dict)
        else "en"
    )
    task_domain = str(task.domain or "general").strip().lower()

    task.claimed_by = None
    task.claimed_until = None
    if task.status != "pending":
        task.status = "pending"
    task.save(update_fields=["claimed_by", "claimed_until", "status", "updated_at"])

    audit_meta: dict[str, Any] = {
        "task_id": str(task.id),
        "annotation_id": str(annotation.id),
        "submitted_preference": annotation.preference,
        "domain": task_domain,
        "language": ann_lang,
        "is_correct": is_correct,
    }

    if task.organization_id:
        cal, _created = AnnotatorCalibration.objects.select_for_update().get_or_create(
            organization_id=task.organization_id,
            user_id=annotation.annotator_id,
        )
        cal.gold_evaluated_count += 1
        if is_correct:
            cal.gold_correct_count += 1
        cal.accuracy_rate, cal.skill_weight = compute_bayesian_skill_weight(
            cal.gold_correct_count,
            cal.gold_evaluated_count,
        )
        cal.language_skill_vectors = _update_dimension_vector(
            cal.language_skill_vectors,
            ann_lang,
            is_correct,
        )
        cal.domain_skill_vectors = _update_dimension_vector(
            cal.domain_skill_vectors,
            task_domain,
            is_correct,
        )
        cal.last_calibrated_at = timezone.now()
        cal.save(
            update_fields=[
                "gold_evaluated_count",
                "gold_correct_count",
                "accuracy_rate",
                "skill_weight",
                "language_skill_vectors",
                "domain_skill_vectors",
                "last_calibrated_at",
                "updated_at",
            ]
        )

        cal_event = {
            "user_id": str(annotation.annotator_id),
            "task_id": str(task.id),
            "domain": task_domain,
            "language": ann_lang,
            "is_correct": is_correct,
            "gold_evaluated_count": cal.gold_evaluated_count,
            "gold_correct_count": cal.gold_correct_count,
            "accuracy_rate": cal.accuracy_rate,
            "skill_weight": cal.skill_weight,
        }
        audit_meta.update(
            {
                "gold_evaluated_count": cal.gold_evaluated_count,
                "gold_correct_count": cal.gold_correct_count,
                "accuracy_rate": cal.accuracy_rate,
                "skill_weight": cal.skill_weight,
            }
        )
        enqueue_outbox_event(
            organization_id=str(task.organization_id),
            event_type="annotator.calibrated",
            payload=cal_event,
        )

    annotations = list(TaskAnnotation.objects.filter(task=task).order_by("created_at"))
    counts = Counter(a.preference for a in annotations)
    mean_scores: dict[str, float] = {}
    for metric in ("overall", "helpfulness", "harmlessness", "honesty"):
        vals = [
            float(raw)
            for a in annotations
            if isinstance(a.rubric_scores, dict)
            and isinstance((raw := a.rubric_scores.get(metric)), (int, float))
        ]
        if vals:
            mean_scores[metric] = round(sum(vals) / len(vals), 2)

    blind_consensus: dict[str, Any] = {
        "annotation_count": len(annotations),
        "required_annotations": task.required_annotations,
        "consensus_reached": False,
        "awaiting_adjudication": False,
        "consensus_choice": "",
        "consensus_score": None,
        "choice_distribution": dict(counts),
        "mean_scores": mean_scores,
    }
    return blind_consensus, audit_meta


def get_organization_calibration_leaderboard(
    org: "Organization",
    *,
    domain: str | None = None,
    language: str | None = None,
) -> tuple[dict[str, Any], str]:
    """Build replica-routed empirical calibration & domain/language specialist leaderboard."""
    with use_read_replica() as query_target:
        calibrations = list(
            AnnotatorCalibration.objects.filter(organization_id=org.id)
            .select_related("user")
            .order_by("-skill_weight", "-gold_evaluated_count", "user__email")
        )
        member_count = OrganizationMember.objects.filter(organization_id=org.id).count()
        gold_task_count = Task.objects.filter(
            organization_id=org.id,
            is_active=True,
            is_gold=True,
        ).count()

    calibrated_rows = [c for c in calibrations if c.gold_evaluated_count > 0]
    calibrated_count = len(calibrated_rows)
    mean_accuracy = (
        round(sum(c.accuracy_rate for c in calibrated_rows) / calibrated_count, 4)
        if calibrated_count > 0
        else None
    )
    mean_weight = (
        round(sum(c.skill_weight for c in calibrated_rows) / calibrated_count, 4)
        if calibrated_count > 0
        else 1.0
    )

    annotators_out: list[dict[str, Any]] = []
    for c in calibrations:
        dom_vecs = c.domain_skill_vectors if isinstance(c.domain_skill_vectors, dict) else {}
        lang_vecs = c.language_skill_vectors if isinstance(c.language_skill_vectors, dict) else {}

        if domain and domain not in dom_vecs:
            continue
        if language and language not in lang_vecs:
            continue

        specialist_domains = sorted(
            k
            for k, v in dom_vecs.items()
            if isinstance(v, dict)
            and int(v.get("evaluated", 0)) > 0
            and float(v.get("skill_weight", 0.0)) >= SPECIALIST_WEIGHT_THRESHOLD
        )
        effective_w = resolve_effective_skill_weight(
            c,
            domain=domain or "general",
            language=language or "en",
        )
        annotators_out.append(
            {
                "user_id": str(c.user_id),
                "email": c.user.email,
                "gold_evaluated_count": c.gold_evaluated_count,
                "gold_correct_count": c.gold_correct_count,
                "accuracy_rate": c.accuracy_rate,
                "skill_weight": c.skill_weight,
                "effective_skill_weight": effective_w,
                "domain_skill_vectors": dom_vecs,
                "language_skill_vectors": lang_vecs,
                "specialist_domains": specialist_domains,
                "status": (
                    "trusted"
                    if c.gold_evaluated_count > 0 and c.skill_weight >= 1.0
                    else ("probation" if c.gold_evaluated_count > 0 else "uncalibrated")
                ),
                "last_calibrated_at": (
                    c.last_calibrated_at.isoformat() if c.last_calibrated_at else None
                ),
            }
        )

    if domain or language:
        annotators_out.sort(
            key=lambda item: (
                -float(item["effective_skill_weight"]),
                -int(item["gold_evaluated_count"]),
                str(item["email"]),
            )
        )

    payload: dict[str, Any] = {
        "organization_id": str(org.id),
        "gold_task_count": gold_task_count,
        "total_members": member_count,
        "calibrated_annotators": calibrated_count,
        "uncalibrated_members": max(0, member_count - calibrated_count),
        "mean_accuracy_rate": mean_accuracy,
        "mean_skill_weight": mean_weight,
        "filters": {"domain": domain, "language": language},
        "annotators": annotators_out,
        "query_target": query_target,
    }
    return payload, query_target
