"""Task API views with query-aware Redis caching, RLHF leasing/consensus, bulk ingest, and JSONL export."""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Iterator
from datetime import timedelta
from typing import Any
from urllib.parse import urlencode

from django.conf import settings
from django.core.cache import cache
from django.db import IntegrityError, connection, transaction
from django.db.models import (
    Case,
    Count,
    Exists,
    F,
    FloatField,
    IntegerField,
    OuterRef,
    Q,
    QuerySet,
    Value,
    When,
)
from django.db.models.functions import Coalesce
from django.http import StreamingHttpResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone

from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema
from rest_framework import filters, status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import BaseRenderer, JSONRenderer
from rest_framework.request import Request
from rest_framework.response import Response

from apps.core.db_router import use_read_replica
from apps.core.models import AuditLog
from apps.core.outbox import enqueue_outbox_event
from apps.core.rls import get_effective_rls_scope, rls_context
from apps.core.views import record_cache_hit, record_cache_miss
from apps.tasks.calibration import evaluate_gold_annotation, get_annotator_claim_routing
from apps.tasks.consensus import evaluate_task_consensus
from apps.tasks.filters import TaskFilter
from apps.tasks.models import Task, TaskAnnotation
from apps.tasks.serializers import (
    TaskAdjudicateSerializer,
    TaskAnnotationSerializer,
    TaskClaimRequestSerializer,
    TaskSerializer,
    TaskUncertaintyTriageSerializer,
)

logger = logging.getLogger(__name__)

CACHE_TTL_LIST: int = settings.CACHE_TTL["task_list"]
CACHE_TTL_DETAIL: int = settings.CACHE_TTL["task_detail"]
MAX_BULK_CREATE_TASKS: int = 100


class JSONLinesRenderer(BaseRenderer):
    """DRF renderer enabling ``?format=jsonl`` content negotiation for NDJSON exports."""

    media_type = "application/x-ndjson"
    format = "jsonl"
    charset = "utf-8"

    def render(
        self,
        data: Any,
        accepted_media_type: str | None = None,
        renderer_context: dict[str, Any] | None = None,
    ) -> bytes:
        if isinstance(data, (bytes, bytearray)):
            return bytes(data)
        return (json.dumps(data, ensure_ascii=False) + "\n").encode("utf-8")


def _cache_key(prefix: str, scope_id: str, lang: str, suffix: str = "") -> str:
    """Build a standardised cache key."""
    return f"mltask:{prefix}:{scope_id}:{lang}:{suffix}"


def _cache_index_key(scope_id: str) -> str:
    """Registry key tracking active dynamic cache keys for ``scope_id``."""
    return f"mltask:cache_index:{scope_id}"


def _scope_id_for_request(request: Request) -> str:
    """Return tenant scope identifier (``org:<uuid>`` or ``<user_uuid>``)."""
    organization = getattr(request, "organization", None)
    if organization is not None:
        return f"org:{organization.id}"
    return str(request.user.id)


def _is_org_gold_admin(request: Request) -> bool:
    """Return True when the request is scoped to an org with admin/owner gold visibility."""
    if getattr(request, "organization", None) is None:
        return False
    if bool(getattr(request.user, "is_superuser", False)):
        return True
    return getattr(request, "membership_role", None) in ("admin", "owner")


def _query_fingerprint(request: Request) -> str:
    """Deterministic digest of query parameters excluding ``lang``."""
    items: list[tuple[str, str]] = []
    for key in sorted(request.query_params.keys()):
        if key.lower() == "lang":
            continue
        for val in sorted(request.query_params.getlist(key)):
            items.append((key, val))
    if not items:
        return ""
    canonical = urlencode(items)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def register_scope_cache_key(scope_id: str, key: str) -> None:
    """Track ``key`` under ``scope_id`` so mutations can invalidate all variants."""
    idx_key = _cache_index_key(scope_id)
    try:
        tracked = cache.get(idx_key)
        key_set = set(tracked) if isinstance(tracked, (list, set, tuple)) else set()
        if key not in key_set:
            key_set.add(key)
            cache.set(idx_key, list(key_set), timeout=max(CACHE_TTL_LIST, CACHE_TTL_DETAIL))
    except Exception:
        logger.debug("Unable to update cache key index for %s", scope_id, exc_info=True)


def invalidate_task_caches_for_scopes(
    scope_ids: list[str],
    task_id: str | None = None,
) -> None:
    """Invalidate list and detail caches across all configured languages and query variants."""
    languages = [str(code).lower() for code, _ in getattr(settings, "LANGUAGES", [("en", "EN")])]

    for scope_id in set(scope_ids):
        if not scope_id:
            continue
        keys_to_delete: set[str] = set()
        for lang in languages:
            keys_to_delete.add(_cache_key("task_list", scope_id, lang, ""))
            keys_to_delete.add(_cache_key("task_list", scope_id, lang, "adm:"))
            if task_id:
                keys_to_delete.add(_cache_key("task_detail", scope_id, lang, str(task_id)))
                keys_to_delete.add(_cache_key("task_detail", scope_id, lang, f"adm:{task_id}"))

        idx_key = _cache_index_key(scope_id)
        tracked = cache.get(idx_key)
        if isinstance(tracked, (list, set, tuple)):
            keys_to_delete.update(str(k) for k in tracked)
        keys_to_delete.add(idx_key)

        for key in keys_to_delete:
            cache.delete(key)


class TaskViewSet(viewsets.ModelViewSet):
    """CRUD and RLHF workflow endpoint for multilingual tasks."""

    queryset = Task.objects.filter(is_active=True)
    serializer_class = TaskSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [
        DjangoFilterBackend,
        filters.OrderingFilter,
    ]
    filterset_class = TaskFilter
    ordering_fields = ["created_at", "updated_at", "status", "priority"]

    def get_queryset(self) -> QuerySet[Task]:
        """Return optimized tenant-scoped or user-scoped queryset without N+1 queries."""
        base_qs = (
            Task.objects.filter(is_active=True)
            .select_related("user", "organization")
            .prefetch_related("translations")
            .annotate(annotation_count_val=Count("annotations", distinct=True))
            .order_by("-created_at", "-id")
        )
        organization = getattr(self.request, "organization", None)
        if organization is not None:
            return base_qs.filter(organization=organization)
        return base_qs.filter(user=self.request.user)

    def list(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """List tasks with query-aware, language-scoped, gold-blindness-safe Redis caching."""
        scope_id = _scope_id_for_request(request)
        lang = getattr(request, "language", "en")
        q_fingerprint = _query_fingerprint(request)
        suffix = f"adm:{q_fingerprint}" if _is_org_gold_admin(request) else q_fingerprint
        cache_key = _cache_key("task_list", scope_id, lang, suffix)

        cached = cache.get(cache_key)
        if cached is not None:
            record_cache_hit()
            return Response(cached)

        record_cache_miss()
        response = super().list(request, *args, **kwargs)
        cache.set(cache_key, response.data, timeout=CACHE_TTL_LIST)
        register_scope_cache_key(scope_id, cache_key)
        return response

    def retrieve(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """Retrieve a single task with language-scoped, gold-blindness-safe Redis caching."""
        scope_id = _scope_id_for_request(request)
        lang = getattr(request, "language", "en")
        task_id = str(kwargs.get("pk", ""))
        suffix = f"adm:{task_id}" if _is_org_gold_admin(request) else task_id
        cache_key = _cache_key("task_detail", scope_id, lang, suffix)

        cached = cache.get(cache_key)
        if cached is not None:
            record_cache_hit()
            return Response(cached)

        record_cache_miss()
        response = super().retrieve(request, *args, **kwargs)
        cache.set(cache_key, response.data, timeout=CACHE_TTL_DETAIL)
        register_scope_cache_key(scope_id, cache_key)
        return response

    @action(detail=True, methods=["post"], url_path="restore")
    def restore(self, request: Request, pk: str | None = None) -> Response:
        """Restore a soft-deleted task scoped to the user or active organization."""
        base_qs = Task.objects.select_related("user", "organization").prefetch_related(
            "translations"
        )
        organization = getattr(request, "organization", None)
        if organization is not None:
            scoped_qs = base_qs.filter(organization=organization)
        else:
            scoped_qs = base_qs.filter(user=request.user)

        task = get_object_or_404(scoped_qs, pk=pk)

        if task.is_active:
            return Response(
                {"error": "Task is already active."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        task.is_active = True
        task.save(update_fields=["is_active", "updated_at"])
        self._invalidate_for_task(task)
        serializer = self.get_serializer(task)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=False, methods=["post"], url_path="claim")
    def claim(self, request: Request) -> Response:
        """Atomically claim the next available unannotated RLHF task with a time-bounded lease."""
        req_serializer = TaskClaimRequestSerializer(data=request.data)
        req_serializer.is_valid(raise_exception=True)
        lease_seconds = int(req_serializer.validated_data["lease_seconds"])
        priority_filter = req_serializer.validated_data["priority"]
        domain_filter = req_serializer.validated_data["domain"]
        difficulty_filter = req_serializer.validated_data["difficulty"]

        organization = getattr(request, "organization", None)
        now = timezone.now()

        with transaction.atomic():
            if organization is not None:
                inject_gold_first, is_probation, trusted_domains = get_annotator_claim_routing(
                    organization,
                    request.user,
                )
            else:
                inject_gold_first, is_probation, trusted_domains = False, False, []

            already_annotated = TaskAnnotation.objects.filter(
                task=OuterRef("pk"),
                annotator=request.user,
            )
            priority_rank = Case(
                When(priority="critical", then=Value(4)),
                When(priority="high", then=Value(3)),
                When(priority="medium", then=Value(2)),
                default=Value(1),
                output_field=IntegerField(),
            )
            gold_rank = Case(
                When(is_gold=True, then=Value(1 if inject_gold_first else 0)),
                default=Value(0 if inject_gold_first else 1),
                output_field=IntegerField(),
            )
            specialist_rank = (
                Case(
                    When(domain__in=trusted_domains, then=Value(1)),
                    default=Value(0),
                    output_field=IntegerField(),
                )
                if trusted_domains
                else Value(0, output_field=IntegerField())
            )
            uncertainty_rank = Coalesce(
                F("uncertainty_score"),
                Value(0.0),
                output_field=FloatField(),
            )
            capacity_filter = (
                Q(is_gold=True) | Q(is_gold=False, existing_ann_count__lt=F("required_annotations"))
                if organization is not None
                else Q(existing_ann_count__lt=F("required_annotations"))
            )
            candidates = (
                Task.objects.filter(
                    is_active=True,
                    status__in=["pending", "in_progress"],
                )
                .annotate(
                    existing_ann_count=Count("annotations", distinct=True),
                    has_my_annotation=Exists(already_annotated),
                    priority_rank=priority_rank,
                    gold_rank=gold_rank,
                    specialist_rank=specialist_rank,
                    uncertainty_rank=uncertainty_rank,
                )
                .filter(has_my_annotation=False)
                .filter(capacity_filter)
                .filter(
                    Q(claimed_until__isnull=True)
                    | Q(claimed_until__lte=now)
                    | Q(claimed_by=request.user)
                )
            )
            if organization is not None:
                candidates = candidates.filter(organization=organization)
                if is_probation:
                    candidates = candidates.exclude(is_gold=False, difficulty="expert")
            else:
                candidates = candidates.filter(user=request.user)

            if priority_filter:
                candidates = candidates.filter(priority=priority_filter)
            if domain_filter:
                candidates = candidates.filter(domain=domain_filter)
            if difficulty_filter:
                candidates = candidates.filter(difficulty=difficulty_filter)

            candidate_id_list = list(
                candidates.order_by(
                    "-gold_rank",
                    "-specialist_rank",
                    "-priority_rank",
                    "-uncertainty_rank",
                    "created_at",
                ).values_list("id", flat=True)[:25]
            )
            if not candidate_id_list:
                return Response(
                    {"detail": "No eligible tasks available for claiming."},
                    status=status.HTTP_204_NO_CONTENT,
                )

            lock_qs = (
                Task.objects.filter(id__in=candidate_id_list)
                .filter(
                    Q(claimed_until__isnull=True)
                    | Q(claimed_until__lte=now)
                    | Q(claimed_by=request.user)
                )
                .annotate(
                    priority_rank=priority_rank,
                    gold_rank=gold_rank,
                    specialist_rank=specialist_rank,
                    uncertainty_rank=uncertainty_rank,
                )
                .order_by(
                    "-gold_rank",
                    "-specialist_rank",
                    "-priority_rank",
                    "-uncertainty_rank",
                    "created_at",
                )
            )
            if connection.features.has_select_for_update_skip_locked:
                lock_qs = lock_qs.select_for_update(skip_locked=True)
            elif connection.features.has_select_for_update:
                lock_qs = lock_qs.select_for_update()

            claimed_task: Task | None = lock_qs.first()

            if claimed_task is None:
                return Response(
                    {"detail": "No eligible tasks available for claiming."},
                    status=status.HTTP_204_NO_CONTENT,
                )

            claimed_task.claimed_by = request.user
            claimed_task.claimed_until = now + timedelta(seconds=lease_seconds)
            if claimed_task.status == "pending":
                claimed_task.status = "in_progress"
            claimed_task.save(update_fields=["claimed_by", "claimed_until", "status", "updated_at"])

        refreshed = self.get_queryset().get(pk=claimed_task.pk)
        self._invalidate_for_task(refreshed)
        AuditLog.objects.create(
            organization=organization,
            user=request.user,
            action="task_claimed",
            resource_type="Task",
            resource_id=str(refreshed.id),
            metadata={"lease_seconds": lease_seconds},
        )
        return Response(self.get_serializer(refreshed).data, status=status.HTTP_200_OK)

    @action(detail=True, methods=["get", "post"], url_path="annotations")
    def annotations(self, request: Request, pk: str | None = None) -> Response:
        """List annotations for a task or submit a structured RLHF annotation."""
        task = self.get_object()

        if request.method == "GET":
            items = task.annotations.select_related("annotator").order_by("created_at")
            return Response(TaskAnnotationSerializer(items, many=True).data)

        now = timezone.now()
        if (
            task.claimed_by_id is not None
            and task.claimed_by_id != request.user.id
            and task.claimed_until is not None
            and task.claimed_until > now
        ):
            return Response(
                {"error": "Task is currently leased to another annotator."},
                status=status.HTTP_409_CONFLICT,
            )

        if TaskAnnotation.objects.filter(task=task, annotator=request.user).exists():
            return Response(
                {"error": "You have already submitted an annotation for this task."},
                status=status.HTTP_409_CONFLICT,
            )

        payload = dict(request.data) if isinstance(request.data, dict) else {}
        if "language" not in payload:
            payload["language"] = getattr(request, "language", "en") or "en"

        serializer = TaskAnnotationSerializer(data=payload)
        serializer.is_valid(raise_exception=True)

        gold_audit_meta: dict[str, Any] | None = None
        try:
            with transaction.atomic():
                annotation = serializer.save(task=task, annotator=request.user)
                if task.is_gold:
                    consensus_summary, gold_audit_meta = evaluate_gold_annotation(task, annotation)
                else:
                    consensus_summary = evaluate_task_consensus(task)
        except IntegrityError:
            return Response(
                {"error": "You have already submitted an annotation for this task."},
                status=status.HTTP_409_CONFLICT,
            )

        self._invalidate_for_task(task)
        organization = getattr(request, "organization", None) or task.organization
        AuditLog.objects.create(
            organization=organization,
            user=request.user,
            action="task_annotated",
            resource_type="TaskAnnotation",
            resource_id=str(annotation.id),
            metadata={
                "task_id": str(task.id),
                "preference": annotation.preference,
                "consensus_reached": consensus_summary["consensus_reached"],
            },
        )
        if gold_audit_meta is not None:
            AuditLog.objects.create(
                organization=organization,
                user=request.user,
                action="gold_task_evaluated",
                resource_type="AnnotatorCalibration",
                resource_id=str(request.user.id),
                metadata=gold_audit_meta,
            )
        return Response(
            {
                "annotation": TaskAnnotationSerializer(annotation).data,
                "consensus": consensus_summary,
            },
            status=status.HTTP_201_CREATED,
        )

    @action(detail=True, methods=["post"], url_path="adjudicate")
    def adjudicate(self, request: Request, pk: str | None = None) -> Response:
        """Adjudicate a split-vote task and finalize its gold consensus label."""
        task = self.get_object()
        serializer = TaskAdjudicateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        choice = str(serializer.validated_data["consensus_choice"])
        rationale = str(serializer.validated_data["rationale"])

        with transaction.atomic():
            task.consensus_choice = choice
            task.consensus_score = 1.0
            task.status = "completed"
            task.claimed_by = None
            task.claimed_until = None
            task.save(
                update_fields=[
                    "consensus_choice",
                    "consensus_score",
                    "status",
                    "claimed_by",
                    "claimed_until",
                    "updated_at",
                ]
            )
            if task.organization_id:
                event_data = {
                    "task_id": str(task.id),
                    "consensus_choice": choice,
                    "adjudicated_by": str(request.user.id),
                }
                enqueue_outbox_event(
                    organization_id=str(task.organization_id),
                    event_type="task.consensus_reached",
                    payload=event_data,
                )
                enqueue_outbox_event(
                    organization_id=str(task.organization_id),
                    event_type="task.completed",
                    payload=event_data,
                )

        self._invalidate_for_task(task)
        organization = getattr(request, "organization", None) or task.organization
        AuditLog.objects.create(
            organization=organization,
            user=request.user,
            action="task_adjudicated",
            resource_type="Task",
            resource_id=str(task.id),
            metadata={"consensus_choice": choice, "rationale": rationale},
        )

        refreshed = self.get_queryset().get(pk=task.pk)
        return Response(self.get_serializer(refreshed).data, status=status.HTTP_200_OK)

    @extend_schema(
        operation_id="v1_tasks_triage_uncertainty_create",
        request=TaskUncertaintyTriageSerializer,
        responses={
            200: {"type": "object"},
            400: {"type": "object"},
            429: {"type": "object"},
            502: {"type": "object"},
            503: {"type": "object"},
        },
    )
    @action(detail=True, methods=["post"], url_path="triage-uncertainty")
    def triage_uncertainty(self, request: Request, pk: str | None = None) -> Response:
        """Run active-learning LLM judge triage and promote high-entropy pairs to expert tier."""
        from apps.ai_assist.circuit_breaker import CircuitOpenError, openai_circuit_breaker
        from apps.ai_assist.services import _ai_service
        from apps.core.finops import AIBudgetExceededError

        task = self.get_object()
        serializer = TaskUncertaintyTriageSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        prompt_text = str(serializer.validated_data.get("prompt") or "").strip()
        if not prompt_text:
            prompt_text = str(
                task.safe_translation_getter("description", any_language=True)
                or task.safe_translation_getter("title", any_language=True)
                or ""
            ).strip()
        if not prompt_text:
            return Response(
                {"error": "Task has no prompt/description text to evaluate."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        lang = str(
            serializer.validated_data.get("lang") or getattr(request, "language", "en") or "en"
        )[:10]
        organization = getattr(request, "organization", None) or task.organization
        org_id_str = str(organization.id) if organization is not None else None

        try:
            call_kwargs = {"organization_id": org_id_str} if org_id_str else {}
            triage_result = _ai_service.judge_rlhf_pair(
                user_id=str(request.user.id),
                lang=lang,
                prompt_text=prompt_text,
                response_a=str(serializer.validated_data["response_a"]),
                response_b=str(serializer.validated_data["response_b"]),
                domain=str(task.domain or "general"),
                **call_kwargs,
            )
        except ValueError as exc:
            return Response({"error": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except AIBudgetExceededError as exc:
            return Response(
                {
                    "error": str(exc),
                    "code": "ai_budget_exceeded",
                    "budget": exc.budget_snapshot,
                },
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )
        except CircuitOpenError:
            retry_after = str(openai_circuit_breaker.recovery_timeout)
            return Response(
                {
                    "error": "AI service temporarily unavailable",
                    "retry_after": openai_circuit_breaker.recovery_timeout,
                },
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
                headers={"Retry-After": retry_after},
            )
        except Exception as exc:
            logger.error("Active-learning uncertainty triage failed: %s", exc)
            return Response(
                {"error": "AI service temporarily unavailable"},
                status=status.HTTP_502_BAD_GATEWAY,
            )

        uncertainty_score = float(triage_result["uncertainty_score"])
        should_escalate = bool(triage_result["should_escalate"]) and not task.is_gold
        escalated_now = False

        with transaction.atomic():
            update_fields = ["uncertainty_score", "updated_at"]
            task.uncertainty_score = uncertainty_score
            if should_escalate:
                if task.difficulty != "expert":
                    task.difficulty = "expert"
                    update_fields.append("difficulty")
                if task.priority in ("low", "medium"):
                    task.priority = "high"
                    update_fields.append("priority")
                if not task.auto_escalated:
                    task.auto_escalated = True
                    update_fields.append("auto_escalated")
                escalated_now = True

            task.save(update_fields=update_fields)
            if escalated_now and task.organization_id:
                enqueue_outbox_event(
                    organization_id=str(task.organization_id),
                    event_type="task.uncertainty_escalated",
                    payload={
                        "task_id": str(task.id),
                        "reason": "llm_judge_high_entropy",
                        "domain": task.domain,
                        "difficulty": task.difficulty,
                        "priority": task.priority,
                        "uncertainty_score": uncertainty_score,
                        "shannon_entropy": triage_result["shannon_entropy"],
                        "judge_preference": triage_result["preference"],
                    },
                )

        self._invalidate_for_task(task)
        AuditLog.objects.create(
            organization=organization,
            user=request.user,
            action="task_uncertainty_triaged",
            resource_type="Task",
            resource_id=str(task.id),
            metadata={
                "uncertainty_score": uncertainty_score,
                "shannon_entropy": triage_result["shannon_entropy"],
                "escalated": escalated_now,
                "difficulty": task.difficulty,
            },
        )
        refreshed = self.get_queryset().get(pk=task.pk)
        return Response(
            {
                "task": self.get_serializer(refreshed).data,
                "triage": {
                    **triage_result,
                    "escalated_to_expert": escalated_now,
                },
            },
            status=status.HTTP_200_OK,
        )

    @action(detail=False, methods=["post"], url_path="bulk")
    def bulk(self, request: Request) -> Response:
        """Atomically ingest up to 100 multilingual tasks while enforcing tenant quotas."""
        raw_items: Any = request.data
        if isinstance(raw_items, dict) and "tasks" in raw_items:
            raw_items = raw_items["tasks"]

        if not isinstance(raw_items, list) or not raw_items:
            return Response(
                {"error": "Provide a non-empty list of tasks (up to 100 items)."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if len(raw_items) > MAX_BULK_CREATE_TASKS:
            return Response(
                {
                    "error": f"Bulk creation is limited to {MAX_BULK_CREATE_TASKS} tasks per request."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        organization = getattr(request, "organization", None)
        if organization is not None:
            current_active = Task.objects.filter(organization=organization, is_active=True).count()
            if current_active + len(raw_items) > organization.max_tasks:
                return Response(
                    {
                        "error": (
                            f"Bulk batch ({len(raw_items)}) exceeds remaining organization "
                            f"task quota ({max(0, organization.max_tasks - current_active)} left "
                            f"of {organization.max_tasks})."
                        )
                    },
                    status=status.HTTP_403_FORBIDDEN,
                )

        item_serializers = [
            TaskSerializer(data=item, context=self.get_serializer_context()) for item in raw_items
        ]
        errors: list[dict[str, Any]] = []
        for idx, item_ser in enumerate(item_serializers):
            if not item_ser.is_valid():
                errors.append({"index": idx, "errors": item_ser.errors})
        if errors:
            return Response({"errors": errors}, status=status.HTTP_400_BAD_REQUEST)

        created_tasks: list[Task] = []
        with transaction.atomic():
            for item_ser in item_serializers:
                task_obj: Task = item_ser.save(user=request.user, organization=organization)
                created_tasks.append(task_obj)
                self._schedule_post_create_hooks(task_obj)

        scopes = [str(request.user.id)]
        if organization is not None:
            scopes.append(f"org:{organization.id}")
        invalidate_task_caches_for_scopes(scopes)

        out = TaskSerializer(created_tasks, many=True, context=self.get_serializer_context()).data
        return Response(
            {"count": len(created_tasks), "results": out},
            status=status.HTTP_201_CREATED,
        )

    @extend_schema(responses={200: {"type": "object"}})
    @action(detail=False, methods=["get"], url_path="stats")
    def stats(self, request: Request) -> Response:
        """Aggregate tenant/user RLHF operational metrics routed via the read replica."""
        now = timezone.now()
        organization = getattr(request, "organization", None)

        with use_read_replica() as query_target:
            scoped = Task.objects.filter(is_active=True)
            if organization is not None:
                scoped = scoped.filter(organization=organization)
            else:
                scoped = scoped.filter(user=request.user)

            agg = scoped.aggregate(
                total_tasks=Count("id"),
                pending=Count("id", filter=Q(status="pending")),
                in_progress=Count("id", filter=Q(status="in_progress")),
                completed=Count("id", filter=Q(status="completed")),
                archived=Count("id", filter=Q(status="archived")),
                low=Count("id", filter=Q(priority="low")),
                medium=Count("id", filter=Q(priority="medium")),
                high=Count("id", filter=Q(priority="high")),
                critical=Count("id", filter=Q(priority="critical")),
                consensus_finalized=Count("id", filter=~Q(consensus_choice="")),
                active_leases=Count("id", filter=Q(claimed_until__gt=now)),
            )

            ann_qs = TaskAnnotation.objects.filter(task__is_active=True)
            if organization is not None:
                ann_qs = ann_qs.filter(task__organization=organization)
            else:
                ann_qs = ann_qs.filter(task__user=request.user)
            total_annotations = ann_qs.count()

        payload = {
            "total_tasks": int(agg["total_tasks"] or 0),
            "by_status": {
                "pending": int(agg["pending"] or 0),
                "in_progress": int(agg["in_progress"] or 0),
                "completed": int(agg["completed"] or 0),
                "archived": int(agg["archived"] or 0),
            },
            "by_priority": {
                "low": int(agg["low"] or 0),
                "medium": int(agg["medium"] or 0),
                "high": int(agg["high"] or 0),
                "critical": int(agg["critical"] or 0),
            },
            "consensus_finalized": int(agg["consensus_finalized"] or 0),
            "active_leases": int(agg["active_leases"] or 0),
            "total_annotations": int(total_annotations),
            "query_target": query_target,
        }
        return Response(payload, headers={"X-Query-Target": query_target})

    @action(
        detail=False,
        methods=["get"],
        url_path="export",
        renderer_classes=[JSONRenderer, JSONLinesRenderer],
    )
    def export(self, request: Request) -> StreamingHttpResponse | Response:
        """Stream RLHF dataset records (translations, annotations, consensus) as JSONL or JSON."""
        fmt = (
            request.query_params.get("export_format")
            or request.query_params.get("format")
            or "jsonl"
        ).lower()

        include_gold_param = request.query_params.get("include_gold", "").strip().lower() in (
            "1",
            "true",
            "yes",
        )
        can_export_gold = include_gold_param and (
            getattr(request, "organization", None) is None or _is_org_gold_admin(request)
        )
        export_base_qs = self.filter_queryset(self.get_queryset())
        if not can_export_gold:
            export_base_qs = export_base_qs.filter(is_gold=False)

        qs = export_base_qs.prefetch_related("annotations__annotator").order_by("created_at")

        def _serialize_export_row(task_obj: Task) -> dict[str, Any]:
            translations_map = {
                t.language_code: {"title": t.title, "description": t.description}
                for t in task_obj.translations.all()
            }
            annotations_list = [
                {
                    "id": str(ann.id),
                    "annotator_id": str(ann.annotator_id),
                    "preference": ann.preference,
                    "rubric_scores": ann.rubric_scores,
                    "rationale": ann.rationale,
                    "response_a": ann.response_a,
                    "response_b": ann.response_b,
                    "duration_seconds": ann.duration_seconds,
                    "created_at": ann.created_at.isoformat(),
                }
                for ann in task_obj.annotations.all()
            ]
            return {
                "id": str(task_obj.id),
                "status": task_obj.status,
                "priority": task_obj.priority,
                "domain": task_obj.domain,
                "difficulty": task_obj.difficulty,
                "required_annotations": task_obj.required_annotations,
                "consensus_choice": task_obj.consensus_choice,
                "consensus_score": task_obj.consensus_score,
                "translations": translations_map,
                "annotations": annotations_list,
                "created_at": task_obj.created_at.isoformat(),
            }

        organization = getattr(request, "organization", None)
        AuditLog.objects.create(
            organization=organization,
            user=request.user,
            action="exported",
            resource_type="Task",
            resource_id="dataset",
            metadata={"format": fmt},
        )

        if fmt == "json":
            with use_read_replica() as query_target:
                rows = [_serialize_export_row(t) for t in qs]
            return Response(rows, headers={"X-Query-Target": query_target})

        captured_scope = get_effective_rls_scope()
        with use_read_replica() as query_target:
            resolved_target = query_target

        def _jsonl_stream() -> Iterator[bytes]:
            with rls_context(
                organization_id=captured_scope.organization_id or None,
                user_id=captured_scope.user_id or None,
                enforced=captured_scope.enforced,
            ):
                with use_read_replica():
                    for task_obj in qs:
                        line = (
                            json.dumps(_serialize_export_row(task_obj), ensure_ascii=False) + "\n"
                        )
                        yield line.encode("utf-8")

        response = StreamingHttpResponse(_jsonl_stream(), content_type="application/x-ndjson")
        response["Content-Disposition"] = 'attachment; filename="rlhf-tasks-export.jsonl"'
        response["X-Query-Target"] = resolved_target
        return response

    def _schedule_post_create_hooks(self, instance: Task) -> None:
        """Persist transactional outbox webhook event and schedule post-commit auto-translation."""
        auto_translate = bool(getattr(instance, "_auto_translate_requested", False))
        seed_title = instance.safe_translation_getter("title", any_language=True) or ""
        seed_desc = instance.safe_translation_getter("description", any_language=True) or ""
        seed_input = f"{seed_title}\n{seed_desc}".strip()
        task_id_str = str(instance.id)
        org_id_str = str(instance.organization_id) if instance.organization_id else None

        if org_id_str:
            enqueue_outbox_event(
                organization_id=org_id_str,
                event_type="task.created",
                payload={
                    "task_id": task_id_str,
                    "status": instance.status,
                    "priority": instance.priority,
                },
            )

        if auto_translate and seed_input:

            def _on_commit() -> None:
                from apps.tasks.tasks import generate_task_translations

                try:
                    generate_task_translations.delay(task_id_str, seed_input)
                except Exception:
                    logger.warning("Failed to enqueue auto-translation for task %s", task_id_str)

            transaction.on_commit(_on_commit)

    def perform_create(self, serializer: Any) -> Task:
        """Create task bound to user (and active organization), invalidate caches, and trigger hooks."""
        organization = getattr(self.request, "organization", None)
        with transaction.atomic():
            instance: Task = serializer.save(user=self.request.user, organization=organization)
            self._schedule_post_create_hooks(instance)
        self._invalidate_for_task(instance)
        return instance

    def perform_update(self, serializer: Any) -> Task:
        """Update task, invalidate caches, and notify webhooks atomically via outbox on completion."""
        previous_status = serializer.instance.status
        with transaction.atomic():
            instance: Task = serializer.save()
            if (
                previous_status != "completed"
                and instance.status == "completed"
                and instance.organization_id
            ):
                enqueue_outbox_event(
                    organization_id=str(instance.organization_id),
                    event_type="task.completed",
                    payload={"task_id": str(instance.id), "status": instance.status},
                )
        self._invalidate_for_task(instance)
        return instance

    def perform_destroy(self, instance: Task) -> None:
        """Soft-delete task and invalidate detail + list caches across all languages."""
        instance.delete()
        self._invalidate_for_task(instance)

    def _invalidate_for_task(self, instance: Task) -> None:
        """Invalidate caches for the requesting user, task owner, and task organization."""
        scopes = [str(self.request.user.id), str(instance.user_id)]
        if instance.organization_id:
            scopes.append(f"org:{instance.organization_id}")
        organization = getattr(self.request, "organization", None)
        if organization is not None:
            scopes.append(f"org:{organization.id}")
        invalidate_task_caches_for_scopes(scopes, task_id=str(instance.id))

    def _invalidate_list_cache(self) -> None:
        """Backward-compatible helper to invalidate all list caches for current scope."""
        invalidate_task_caches_for_scopes([_scope_id_for_request(self.request)])

    def _invalidate_detail_cache(self, task_id: Any) -> None:
        """Backward-compatible helper to invalidate detail caches for current scope."""
        invalidate_task_caches_for_scopes(
            [_scope_id_for_request(self.request)],
            task_id=str(task_id),
        )
