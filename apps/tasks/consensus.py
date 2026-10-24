"""Inter-annotator agreement (IAA) & domain/language skill-weighted consensus engine."""

from __future__ import annotations

from collections import Counter
from typing import Any

from apps.core.outbox import enqueue_outbox_event
from apps.tasks.calibration import resolve_effective_skill_weight
from apps.tasks.models import AnnotatorCalibration, Task, TaskAnnotation
from apps.tasks.uncertainty import compute_preference_uncertainty


def _score_val(ann: TaskAnnotation, key: str) -> float | None:
    scores = ann.rubric_scores if isinstance(ann.rubric_scores, dict) else {}
    raw = scores.get(key)
    return float(raw) if isinstance(raw, (int, float)) else None


def evaluate_task_consensus(task: Task) -> dict[str, Any]:
    """Recompute empirical domain/language skill-weighted IAA and lifecycle status for ``task``."""
    annotations = list(TaskAnnotation.objects.filter(task=task).order_by("created_at"))
    total = len(annotations)
    if total == 0:
        return {
            "annotation_count": 0,
            "required_annotations": task.required_annotations,
            "consensus_reached": False,
            "awaiting_adjudication": False,
            "consensus_choice": "",
            "consensus_score": None,
            "skill_weighted": False,
            "mean_scores": {},
        }

    cal_map: dict[Any, AnnotatorCalibration] = {}
    if task.organization_id:
        annotator_ids = [a.annotator_id for a in annotations]
        cal_map = {
            c.user_id: c
            for c in AnnotatorCalibration.objects.filter(
                organization_id=task.organization_id,
                user_id__in=annotator_ids,
                gold_evaluated_count__gt=0,
            )
        }

    counts = Counter(a.preference for a in annotations)
    unweighted_ranked = counts.most_common()
    unweighted_ratio = round(unweighted_ranked[0][1] / total, 4)

    task_domain = str(task.domain or "general").strip().lower()
    weighted_totals: dict[str, float] = {}
    annotator_weights: list[tuple[TaskAnnotation, float]] = []
    for ann in annotations:
        ann_lang = (
            str(ann.rubric_scores.get("language") or "en").strip().lower()
            if isinstance(ann.rubric_scores, dict)
            else "en"
        )
        w = resolve_effective_skill_weight(
            cal_map.get(ann.annotator_id),
            domain=task_domain,
            language=ann_lang,
        )
        annotator_weights.append((ann, w))
        weighted_totals[ann.preference] = weighted_totals.get(ann.preference, 0.0) + w

    total_weight = sum(weighted_totals.values())
    ranked_weighted = sorted(
        weighted_totals.items(),
        key=lambda kv: (kv[1], counts[kv[0]]),
        reverse=True,
    )
    top_choice, top_weight = ranked_weighted[0]
    has_unique_leader = (
        len(ranked_weighted) == 1 or (ranked_weighted[0][1] - ranked_weighted[1][1]) > 1e-6
    )
    agreement_ratio = round(top_weight / total_weight, 4) if total_weight > 0 else unweighted_ratio

    mean_scores: dict[str, float] = {}
    for metric in ("overall", "helpfulness", "harmlessness", "honesty"):
        pairs = [
            (v, w) for ann, w in annotator_weights if (v := _score_val(ann, metric)) is not None
        ]
        if pairs:
            denom = sum(w for _, w in pairs)
            if denom > 0:
                mean_scores[metric] = round(sum(v * w for v, w in pairs) / denom, 2)

    consensus_reached = False
    awaiting_adjudication = False
    uncertainty_meta = compute_preference_uncertainty(
        weighted_totals,
        organization_id=str(task.organization_id) if task.organization_id else None,
        domain=task_domain,
    )
    task.claimed_by = None
    task.claimed_until = None
    task.consensus_score = agreement_ratio
    task.uncertainty_score = float(uncertainty_meta["uncertainty_score"])
    escalated_on_split = False

    if total >= task.required_annotations:
        if has_unique_leader and agreement_ratio > 0.5:
            consensus_reached = True
            task.consensus_choice = top_choice
            task.status = "completed"
        else:
            awaiting_adjudication = True
            task.consensus_choice = ""
            if task.status == "pending":
                task.status = "in_progress"
            if not task.is_gold and (task.difficulty != "expert" or not task.auto_escalated):
                task.difficulty = "expert"
                task.auto_escalated = True
                escalated_on_split = True
    else:
        task.consensus_choice = ""
        if task.status == "pending":
            task.status = "in_progress"

    task.save(
        update_fields=[
            "claimed_by",
            "claimed_until",
            "consensus_score",
            "consensus_choice",
            "uncertainty_score",
            "difficulty",
            "auto_escalated",
            "status",
            "updated_at",
        ]
    )

    if escalated_on_split and task.organization_id:
        enqueue_outbox_event(
            organization_id=str(task.organization_id),
            event_type="task.uncertainty_escalated",
            payload={
                "task_id": str(task.id),
                "reason": "split_vote_deadlock",
                "uncertainty_score": task.uncertainty_score,
                "shannon_entropy": uncertainty_meta["shannon_entropy"],
                "difficulty": task.difficulty,
                "annotation_count": total,
            },
        )

    if consensus_reached and task.organization_id:
        org_id = str(task.organization_id)
        event_data = {
            "task_id": str(task.id),
            "domain": task.domain,
            "difficulty": task.difficulty,
            "consensus_choice": task.consensus_choice,
            "consensus_score": task.consensus_score,
            "annotation_count": total,
            "skill_weighted": bool(cal_map),
            "mean_scores": mean_scores,
        }
        enqueue_outbox_event(
            organization_id=org_id,
            event_type="task.consensus_reached",
            payload=event_data,
        )
        enqueue_outbox_event(
            organization_id=org_id,
            event_type="task.completed",
            payload=event_data,
        )

    if (
        (consensus_reached or awaiting_adjudication)
        and task.organization is not None
        and not task.is_gold
        and task.judge_uncertainty_score is not None
    ):
        from apps.tasks.uncertainty import calibrate_organization_domain_thresholds

        calibrate_organization_domain_thresholds(
            task.organization,
            min_samples=3,
            target_domain=task_domain,
        )

    return {
        "annotation_count": total,
        "required_annotations": task.required_annotations,
        "consensus_reached": consensus_reached,
        "awaiting_adjudication": awaiting_adjudication,
        "consensus_choice": task.consensus_choice,
        "consensus_score": task.consensus_score,
        "unweighted_agreement_score": unweighted_ratio,
        "uncertainty_score": task.uncertainty_score,
        "shannon_entropy": uncertainty_meta["shannon_entropy"],
        "auto_escalated": task.auto_escalated,
        "skill_weighted": bool(cal_map),
        "domain": task.domain,
        "difficulty": task.difficulty,
        "choice_distribution": dict(counts),
        "weighted_distribution": {k: round(v, 4) for k, v in weighted_totals.items()},
        "mean_scores": mean_scores,
    }
