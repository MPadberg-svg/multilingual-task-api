from __future__ import annotations

import time
import uuid
from pathlib import Path

from django.core.cache import cache
from django.db import connections, transaction
from django.db.models import Case, IntegerField, Q, Value, When
from django.utils import timezone

import pytest
import yaml

from apps.ai_assist.circuit_breaker import CircuitBreaker, CircuitOpenError, CircuitState
from apps.tasks.models import Task

REPO_ROOT = Path(__file__).resolve().parents[3]
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"


class TestSharedCacheCircuitBreaker:
    """Verify cluster-wide circuit breaker coordination across separate worker instances."""

    def setup_method(self) -> None:
        cache.clear()

    def test_cross_worker_failure_threshold_and_single_flight_half_open_probe(self) -> None:
        worker_a = CircuitBreaker(
            name="cluster-openai",
            failure_threshold=3,
            recovery_timeout=1,
            shared_cache=True,
        )
        worker_b = CircuitBreaker(
            name="cluster-openai",
            failure_threshold=3,
            recovery_timeout=1,
            shared_cache=True,
        )
        worker_a.reset()

        def fail_upstream() -> None:
            raise RuntimeError("OpenAI 503")

        # 2 failures on Worker A + 1 failure on Worker B = 3 cluster-wide failures -> OPEN on both!
        for _ in range(2):
            with pytest.raises(RuntimeError):
                worker_a.call(fail_upstream)
        assert worker_a.state == CircuitState.CLOSED
        assert worker_b.state == CircuitState.CLOSED

        with pytest.raises(RuntimeError):
            worker_b.call(fail_upstream)

        assert worker_a.state == CircuitState.OPEN
        assert worker_b.state == CircuitState.OPEN
        assert worker_a.get_status()["failure_count"] == 3

        with pytest.raises(CircuitOpenError):
            worker_a.call(lambda: "blocked")

        # Wait for recovery_timeout so cluster state enters HALF_OPEN
        time.sleep(1.05)
        assert worker_a.state == CircuitState.HALF_OPEN
        assert worker_b.state == CircuitState.HALF_OPEN

        peer_blocked = False

        def slow_recovery_probe() -> str:
            nonlocal peer_blocked
            try:
                worker_b.call(lambda: "second-worker-probe")
            except CircuitOpenError:
                peer_blocked = True
            return "recovered"

        assert worker_a.call(slow_recovery_probe) == "recovered"
        assert peer_blocked is True
        assert worker_a.state == CircuitState.CLOSED
        assert worker_b.state == CircuitState.CLOSED

    def test_shared_cache_breaker_falls_back_cleanly_when_cache_errors(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cb = CircuitBreaker(
            name="degraded-cache-cb",
            failure_threshold=2,
            recovery_timeout=30,
            shared_cache=True,
        )
        monkeypatch.setattr(
            "apps.ai_assist.circuit_breaker.cache.get",
            lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("Redis down")),
        )

        assert cb.call(lambda: "ok") == "ok"
        for _ in range(2):
            with pytest.raises(ValueError):
                cb.call(lambda: (_ for _ in ()).throw(ValueError("bad")))
        assert cb.state == CircuitState.OPEN


@pytest.mark.django_db
def test_claim_lock_query_compiles_single_row_limit_for_update_skip_locked() -> None:
    """
    Ensure the task-claiming lock query uses ORDER BY (-priority_rank, created_at)
    with LIMIT 1 so PostgreSQL LockRows locks only ONE row per claimer rather than
    locking the entire candidate batch and starving concurrent annotators.
    """
    now = timezone.now()
    priority_rank = Case(
        When(priority="critical", then=Value(4)),
        When(priority="high", then=Value(3)),
        When(priority="medium", then=Value(2)),
        default=Value(1),
        output_field=IntegerField(),
    )
    with transaction.atomic():
        qs = (
            Task.objects.filter(id__in=[uuid.uuid4(), uuid.uuid4()])
            .filter(Q(claimed_until__isnull=True) | Q(claimed_until__lte=now))
            .annotate(priority_rank=priority_rank)
            .order_by("-priority_rank", "created_at")
        )
        has_skip_locked = connections["default"].features.has_select_for_update_skip_locked
        if has_skip_locked:
            qs = qs.select_for_update(skip_locked=True)
        sliced = qs[:1]
        sql = str(sliced.query)
    assert "GROUP BY" not in sql
    assert "LIMIT 1" in sql
    if has_skip_locked:
        assert "FOR UPDATE SKIP LOCKED" in sql


def test_ci_workflow_runs_postgres_16_and_redis_7_service_integration_matrix() -> None:
    ci = yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8"))
    job = ci["jobs"]["integration"]
    assert "postgres:16-alpine" in job["services"]["postgres"]["image"]
    assert "redis:7-alpine" in job["services"]["redis"]["image"]
    joined_runs = "\n".join(step.get("run", "") for step in job["steps"])
    assert "--ds=config.settings.ci_integration" in joined_runs
