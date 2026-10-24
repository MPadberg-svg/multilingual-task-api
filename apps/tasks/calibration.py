"""Gold-standard annotator calibration scoring and replica-routed leaderboard analytics."""

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


def should_inject_gold_task(organization: "Organization", user: Any) -> bool:
    """Return True when ``claim()`` should prioritize an unannotated blind gold calibration task."""
    evaluated = (
        AnnotatorCalibration.objects.filter(organization=organization, user=user)
        .values_list("gold_evaluated_count", flat=True)
        .first()
    )
    if evaluated is None or int(evaluated) < 1:
        return True

    total_org_anns = TaskAnnotation.objects.filter(
        task__organization=organization,
        annotator=user,
    ).count()
    return total_org_anns > 0 and (total_org_anns % CALIBRATION_SPOTCHECK_INTERVAL == 0)


def evaluate_gold_annotation(
    task: Task,
    annotation: TaskAnnotation,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Score a blind gold-task submission, update annotator skill weight, and release the lease.

    Returns ``(blind_consensus_payload, internal_audit_metadata)`` so the HTTP response
    returned to the annotator never discloses that the task was a gold reference item.
    """
    is_correct = bool(task.gold_choice and annotation.preference == task.gold_choice)

    task.claimed_by = None
    task.claimed_until = None
    if task.status != "pending":
        task.status = "pending"
    task.save(update_fields=["claimed_by", "claimed_until", "status", "updated_at"])

    audit_meta: dict[str, Any] = {
        "task_id": str(task.id),
        "annotation_id": str(annotation.id),
        "submitted_preference": annotation.preference,
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
        cal.last_calibrated_at = timezone.now()
        cal.save(
            update_fields=[
                "gold_evaluated_count",
                "gold_correct_count",
                "accuracy_rate",
                "skill_weight",
                "last_calibrated_at",
                "updated_at",
            ]
        )

        cal_event = {
            "user_id": str(annotation.annotator_id),
            "task_id": str(task.id),
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
) -> tuple[dict[str, Any], str]:
    """Build replica-routed empirical calibration leaderboard for organization admins."""
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

    annotators_out = [
        {
            "user_id": str(c.user_id),
            "email": c.user.email,
            "gold_evaluated_count": c.gold_evaluated_count,
            "gold_correct_count": c.gold_correct_count,
            "accuracy_rate": c.accuracy_rate,
            "skill_weight": c.skill_weight,
            "status": (
                "trusted"
                if c.gold_evaluated_count > 0 and c.skill_weight >= 1.0
                else ("probation" if c.gold_evaluated_count > 0 else "uncalibrated")
            ),
            "last_calibrated_at": (
                c.last_calibrated_at.isoformat() if c.last_calibrated_at else None
            ),
        }
        for c in calibrations
    ]

    payload: dict[str, Any] = {
        "organization_id": str(org.id),
        "gold_task_count": gold_task_count,
        "total_members": member_count,
        "calibrated_annotators": calibrated_count,
        "uncalibrated_members": max(0, member_count - calibrated_count),
        "mean_accuracy_rate": mean_accuracy,
        "mean_skill_weight": mean_weight,
        "annotators": annotators_out,
        "query_target": query_target,
    }
    return payload, query_target
