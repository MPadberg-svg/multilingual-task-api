"""Per-tenant AI FinOps budget governance, ledger rollups, and outbox spend alerts.

Enforces monthly token and USD spend ceilings per ``Organization`` (falling back
to plan-tier defaults when custom overrides are ``0``), persists immutable
``AIUsageLog`` ledger entries, and emits deduplicated ``ai.budget_threshold_reached``
and ``ai.budget_exceeded`` webhook events via the Transactional Outbox.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from django.conf import settings
from django.core.cache import cache
from django.db import transaction
from django.db.models import Count, Sum
from django.utils import timezone

from apps.core.db_router import use_read_replica
from apps.core.models import AIUsageLog, Organization
from apps.core.outbox import enqueue_outbox_event
from apps.core.rls import rls_bypass

logger = logging.getLogger(__name__)

_BUDGET_COUNTER_TTL_SECONDS = 45 * 86400  # 45 days covers full UTC billing month + grace
_ORG_BUDGET_CFG_TTL_SECONDS = 60


class AIBudgetExceededError(Exception):
    """Raised before upstream LLM execution when an organization's monthly AI budget is exhausted."""

    def __init__(self, message: str, *, budget_snapshot: dict[str, Any]) -> None:
        super().__init__(message)
        self.budget_snapshot = budget_snapshot


def current_billing_period() -> str:
    """Return current UTC billing period formatted as ``YYYY-MM``."""
    return timezone.now().strftime("%Y-%m")


def _parse_uuid_str(raw: str | None) -> str | None:
    if not raw:
        return None
    try:
        return str(uuid.UUID(str(raw)))
    except (ValueError, TypeError, AttributeError):
        return None


def _coerce_counter(val: Any) -> int | None:
    if val is None or isinstance(val, bool):
        return None
    if isinstance(val, (int, float)):
        return int(val)
    if isinstance(val, str) and val.isdigit():
        return int(val)
    return None


def invalidate_org_budget_cache(organization_id: str) -> None:
    """Invalidate cached budget configuration after an admin updates FinOps ceilings."""
    cache.delete(f"mltask:budget:cfg:{organization_id}")


def resolve_org_ai_budgets(org: Organization) -> dict[str, int]:
    """Compute effective monthly token and cost ceilings for ``org``."""
    token_defaults: dict[str, int] = getattr(settings, "AI_PLAN_MONTHLY_TOKEN_BUDGETS", {})
    cost_defaults: dict[str, int] = getattr(settings, "AI_PLAN_MONTHLY_COST_MICROUSD", {})

    token_budget = (
        int(org.monthly_ai_token_budget)
        if org.monthly_ai_token_budget > 0
        else int(token_defaults.get(org.plan, 100_000))
    )
    cost_microusd = (
        int(org.monthly_ai_cost_budget_microusd)
        if org.monthly_ai_cost_budget_microusd > 0
        else int(cost_defaults.get(org.plan, 5_000_000))
    )
    threshold_pct = max(1, min(100, int(org.ai_budget_alert_threshold_pct or 80)))
    return {
        "token_budget": max(1, token_budget),
        "cost_budget_microusd": max(1, cost_microusd),
        "cost_budget_nanousd": max(1_000, cost_microusd * 1_000),
        "alert_threshold_pct": threshold_pct,
    }


def _get_cached_org_budgets(organization_id: str) -> dict[str, int] | None:
    cfg_key = f"mltask:budget:cfg:{organization_id}"
    cached = cache.get(cfg_key)
    if isinstance(cached, dict) and "token_budget" in cached:
        return {k: int(v) for k, v in cached.items()}

    with rls_bypass():
        org = (
            Organization.objects.filter(id=organization_id, is_active=True)
            .only(
                "id",
                "plan",
                "monthly_ai_token_budget",
                "monthly_ai_cost_budget_microusd",
                "ai_budget_alert_threshold_pct",
            )
            .first()
        )
    if org is None:
        return None

    resolved = resolve_org_ai_budgets(org)
    cache.set(cfg_key, resolved, timeout=_ORG_BUDGET_CFG_TTL_SECONDS)
    return resolved


def _monthly_keys(organization_id: str, period: str) -> tuple[str, str]:
    base = f"mltask:budget:ai:{organization_id}:{period}"
    return f"{base}:tokens", f"{base}:cost_nanousd"


def get_monthly_org_ai_burn(
    organization_id: str,
    billing_period: str | None = None,
) -> tuple[int, int]:
    """Return ``(tokens_used, cost_nanousd)`` for ``organization_id`` in ``billing_period``."""
    period = billing_period or current_billing_period()
    tok_key, cost_key = _monthly_keys(organization_id, period)

    cached_tok = _coerce_counter(cache.get(tok_key))
    cached_cost = _coerce_counter(cache.get(cost_key))
    if cached_tok is not None and cached_cost is not None:
        return cached_tok, cached_cost

    with rls_bypass():
        totals = AIUsageLog.objects.filter(
            organization_id=organization_id,
            billing_period=period,
        ).aggregate(
            tok=Sum("total_tokens"),
            cost=Sum("cost_nanousd"),
        )
    db_tok = int(totals["tok"] or 0)
    db_cost = int(totals["cost"] or 0)

    if cached_tok is None:
        cache.add(tok_key, db_tok, timeout=_BUDGET_COUNTER_TTL_SECONDS)
        cached_tok = _coerce_counter(cache.get(tok_key))
    if cached_cost is None:
        cache.add(cost_key, db_cost, timeout=_BUDGET_COUNTER_TTL_SECONDS)
        cached_cost = _coerce_counter(cache.get(cost_key))

    return (
        db_tok if cached_tok is None else max(db_tok, cached_tok),
        db_cost if cached_cost is None else max(db_cost, cached_cost),
    )


def _increment_monthly_counter(key: str, delta: int, seed_total: int) -> int:
    if delta <= 0:
        cur = _coerce_counter(cache.get(key))
        return seed_total if cur is None else cur
    try:
        return int(cache.incr(key, delta))
    except ValueError:
        if cache.add(key, seed_total, timeout=_BUDGET_COUNTER_TTL_SECONDS):
            return seed_total
        return int(cache.incr(key, delta))


def enforce_org_ai_budget(organization_id: str | None) -> None:
    """Raise ``AIBudgetExceededError`` if ``organization_id`` has exhausted its monthly AI ceiling."""
    valid_org_id = _parse_uuid_str(organization_id)
    if not valid_org_id:
        return

    budgets = _get_cached_org_budgets(valid_org_id)
    if budgets is None:
        return

    period = current_billing_period()
    tokens_used, cost_nanousd = get_monthly_org_ai_burn(valid_org_id, period)
    token_budget = budgets["token_budget"]
    cost_budget_nanousd = budgets["cost_budget_nanousd"]

    if tokens_used >= token_budget or cost_nanousd >= cost_budget_nanousd:
        reason = "token_budget_exceeded" if tokens_used >= token_budget else "cost_budget_exceeded"
        snapshot = {
            "organization_id": valid_org_id,
            "billing_period": period,
            "reason": reason,
            "tokens_used": tokens_used,
            "token_budget": token_budget,
            "cost_used_usd": round(cost_nanousd / 1_000_000_000, 6),
            "cost_budget_usd": round(cost_budget_nanousd / 1_000_000_000, 6),
        }
        raise AIBudgetExceededError(
            "Monthly organization AI budget exceeded.",
            budget_snapshot=snapshot,
        )


def record_org_ai_spend_and_alerts(
    *,
    organization_id: str | None,
    prompt_tokens: int,
    completion_tokens: int,
    cost_nanousd: int,
    user_id: str | None = None,
    operation: str = "chat.completions",
    model_name: str | None = None,
) -> None:
    """Persist ``AIUsageLog``, increment monthly Redis rollups, and emit outbox spend alerts."""
    valid_org_id = _parse_uuid_str(organization_id)
    if not valid_org_id:
        return

    p_tok = max(0, int(prompt_tokens))
    c_tok = max(0, int(completion_tokens))
    total_tok = p_tok + c_tok
    c_nano = max(0, int(cost_nanousd))
    if total_tok == 0 and c_nano == 0:
        return

    valid_user_id = _parse_uuid_str(user_id)
    resolved_model = str(model_name or getattr(settings, "OPENAI_MODEL", "gpt-4o-mini"))[:64]
    period = current_billing_period()

    try:
        with rls_bypass():
            with transaction.atomic():
                org = Organization.objects.filter(id=valid_org_id).first()
                if org is None:
                    return

                AIUsageLog.objects.create(
                    organization=org,
                    user_id=valid_user_id,
                    operation=operation[:50],
                    model_name=resolved_model,
                    prompt_tokens=p_tok,
                    completion_tokens=c_tok,
                    total_tokens=total_tok,
                    cost_nanousd=c_nano,
                    billing_period=period,
                )

                tok_key, cost_key = _monthly_keys(valid_org_id, period)
                prior_tok = _coerce_counter(cache.get(tok_key))
                prior_cost = _coerce_counter(cache.get(cost_key))

                if prior_tok is None or prior_cost is None:
                    agg = AIUsageLog.objects.filter(
                        organization=org,
                        billing_period=period,
                    ).aggregate(tok=Sum("total_tokens"), cost=Sum("cost_nanousd"))
                    db_tok = int(agg["tok"] or total_tok)
                    db_cost = int(agg["cost"] or c_nano)
                    cache.set(tok_key, db_tok, timeout=_BUDGET_COUNTER_TTL_SECONDS)
                    cache.set(cost_key, db_cost, timeout=_BUDGET_COUNTER_TTL_SECONDS)
                    new_tok, new_cost = db_tok, db_cost
                else:
                    new_tok = _increment_monthly_counter(tok_key, total_tok, total_tok)
                    new_cost = _increment_monthly_counter(cost_key, c_nano, c_nano)

                budgets = resolve_org_ai_budgets(org)
                tok_pct = (new_tok / budgets["token_budget"]) * 100.0
                cost_pct = (new_cost / budgets["cost_budget_nanousd"]) * 100.0
                utilization_pct = round(max(tok_pct, cost_pct), 2)

                alert_payload = {
                    "organization_id": valid_org_id,
                    "billing_period": period,
                    "utilization_pct": utilization_pct,
                    "tokens_used": new_tok,
                    "token_budget": budgets["token_budget"],
                    "cost_used_usd": round(new_cost / 1_000_000_000, 6),
                    "cost_budget_usd": round(budgets["cost_budget_nanousd"] / 1_000_000_000, 6),
                }

                if utilization_pct >= float(budgets["alert_threshold_pct"]):
                    threshold_lock = f"mltask:budget:alert:{valid_org_id}:{period}:threshold"
                    if cache.add(threshold_lock, 1, timeout=_BUDGET_COUNTER_TTL_SECONDS):
                        enqueue_outbox_event(
                            organization_id=valid_org_id,
                            event_type="ai.budget_threshold_reached",
                            payload=alert_payload,
                        )

                if utilization_pct >= 100.0:
                    exceeded_lock = f"mltask:budget:alert:{valid_org_id}:{period}:exceeded"
                    if cache.add(exceeded_lock, 1, timeout=_BUDGET_COUNTER_TTL_SECONDS):
                        enqueue_outbox_event(
                            organization_id=valid_org_id,
                            event_type="ai.budget_exceeded",
                            payload=alert_payload,
                        )
    except Exception:
        logger.warning(
            "Unable to persist AI FinOps ledger entry for organization %s",
            valid_org_id,
            exc_info=True,
        )


def get_org_finops_summary(
    org: Organization,
    billing_period: str | None = None,
) -> tuple[dict[str, Any], str]:
    """Compute monthly AI FinOps rollup for ``org`` routed via the read replica when available."""
    period = billing_period or current_billing_period()
    budgets = resolve_org_ai_budgets(org)

    with use_read_replica() as query_target:
        breakdown_rows = list(
            AIUsageLog.objects.filter(organization_id=org.id, billing_period=period)
            .values("operation", "model_name")
            .annotate(
                requests=Count("id"),
                prompt_tokens=Sum("prompt_tokens"),
                completion_tokens=Sum("completion_tokens"),
                total_tokens=Sum("total_tokens"),
                cost_nanousd=Sum("cost_nanousd"),
            )
            .order_by("-total_tokens", "operation")
        )

    db_tok = sum(int(r["total_tokens"] or 0) for r in breakdown_rows)
    db_cost = sum(int(r["cost_nanousd"] or 0) for r in breakdown_rows)
    cache_tok, cache_cost = get_monthly_org_ai_burn(str(org.id), period)
    tokens_used = max(db_tok, cache_tok)
    cost_nanousd = max(db_cost, cache_cost)

    tok_pct = round((tokens_used / budgets["token_budget"]) * 100.0, 2)
    cost_pct = round((cost_nanousd / budgets["cost_budget_nanousd"]) * 100.0, 2)
    utilization_pct = max(tok_pct, cost_pct)

    by_operation = [
        {
            "operation": str(r["operation"]),
            "model_name": str(r["model_name"]),
            "requests": int(r["requests"] or 0),
            "prompt_tokens": int(r["prompt_tokens"] or 0),
            "completion_tokens": int(r["completion_tokens"] or 0),
            "total_tokens": int(r["total_tokens"] or 0),
            "cost_usd": round(int(r["cost_nanousd"] or 0) / 1_000_000_000, 6),
        }
        for r in breakdown_rows
    ]

    summary = {
        "organization_id": str(org.id),
        "plan": org.plan,
        "billing_period": period,
        "custom_overrides": {
            "monthly_ai_token_budget": int(org.monthly_ai_token_budget),
            "monthly_ai_cost_budget_microusd": int(org.monthly_ai_cost_budget_microusd),
            "ai_budget_alert_threshold_pct": int(org.ai_budget_alert_threshold_pct),
        },
        "effective_budgets": {
            "token_budget": budgets["token_budget"],
            "cost_budget_microusd": budgets["cost_budget_microusd"],
            "cost_budget_usd": round(budgets["cost_budget_nanousd"] / 1_000_000_000, 6),
            "alert_threshold_pct": budgets["alert_threshold_pct"],
        },
        "current_usage": {
            "tokens_used": tokens_used,
            "token_utilization_pct": tok_pct,
            "cost_used_usd": round(cost_nanousd / 1_000_000_000, 6),
            "cost_utilization_pct": cost_pct,
            "max_utilization_pct": utilization_pct,
            "budget_exceeded": tokens_used >= budgets["token_budget"]
            or cost_nanousd >= budgets["cost_budget_nanousd"],
        },
        "by_operation": by_operation,
        "query_target": query_target,
    }
    return summary, query_target
