"""Inter-annotator agreement (IAA) & consensus engine for RLHF task annotations."""

from __future__ import annotations

from collections import Counter
from typing import Any

from apps.core.outbox import enqueue_outbox_event
from apps.tasks.models import Task, TaskAnnotation


def _score_val(ann: TaskAnnotation, key: str) -> float | None:
    scores = ann.rubric_scores if isinstance(ann.rubric_scores, dict) else {}
    raw = scores.get(key)
    return float(raw) if isinstance(raw, (int, float)) else None


def evaluate_task_consensus(task: Task) -> dict[str, Any]:
    """Recompute inter-annotator agreement, consensus choice, and lifecycle status for ``task``."""
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
            "mean_scores": {},
        }

    counts = Counter(a.preference for a in annotations)
    ranked = counts.most_common()
    top_choice, top_count = ranked[0]
    has_unique_leader = len(ranked) == 1 or ranked[0][1] > ranked[1][1]
    agreement_ratio = round(top_count / total, 4)

    mean_scores: dict[str, float] = {}
    for metric in ("overall", "helpfulness", "harmlessness", "honesty"):
        vals = [v for a in annotations if (v := _score_val(a, metric)) is not None]
        if vals:
            mean_scores[metric] = round(sum(vals) / len(vals), 2)

    consensus_reached = False
    awaiting_adjudication = False
    task.claimed_by = None
    task.claimed_until = None
    task.consensus_score = agreement_ratio

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
            "status",
            "updated_at",
        ]
    )

    if consensus_reached and task.organization_id:
        org_id = str(task.organization_id)
        event_data = {
            "task_id": str(task.id),
            "consensus_choice": task.consensus_choice,
            "consensus_score": task.consensus_score,
            "annotation_count": total,
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

    return {
        "annotation_count": total,
        "required_annotations": task.required_annotations,
        "consensus_reached": consensus_reached,
        "awaiting_adjudication": awaiting_adjudication,
        "consensus_choice": task.consensus_choice,
        "consensus_score": task.consensus_score,
        "choice_distribution": dict(counts),
        "mean_scores": mean_scores,
    }
