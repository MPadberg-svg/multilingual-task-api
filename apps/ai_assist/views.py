"""AI Assist API views.

Provides three authenticated, throttled endpoints for OpenAI-powered
operations: task translation suggestions, prompt quality evaluation,
and RLHF-style test case generation.

All endpoints:
* Require authentication (``IsAuthenticated``).
* Are rate-limited by ``AIAssistRateThrottle`` (20/hour) and
  ``BurstRateThrottle`` (5/min).
* Return ``400 Bad Request`` on invalid/malicious user input.
* Return ``503 Service Unavailable`` (with ``Retry-After``) when the
  circuit breaker is open.
* Return ``502 Bad Gateway`` if the upstream AI service fails.
"""

from __future__ import annotations

import logging

from drf_spectacular.utils import extend_schema
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response

from apps.ai_assist.circuit_breaker import CircuitOpenError, openai_circuit_breaker
from apps.ai_assist.services import _ai_service
from apps.core.throttling import AIAssistRateThrottle, BurstRateThrottle

logger = logging.getLogger(__name__)


def _extract_string_field(data: object, *keys: str) -> str | None:
    """Safely extract a non-empty string value from request payload."""
    if not isinstance(data, dict):
        return None
    for key in keys:
        if key in data and data[key] is not None:
            val = data[key]
            if not isinstance(val, str):
                raise ValueError(f"Field '{key}' must be a string.")
            if val.strip():
                return val
    return ""


def _resolve_lang_param(request: Request) -> str:
    raw_lang = request.data.get("lang") if isinstance(request.data, dict) else None
    if raw_lang is not None and not isinstance(raw_lang, str):
        raise ValueError("Field 'lang' must be a string.")
    resolved = (raw_lang or getattr(request, "language", "en") or "en").strip().lower()
    return resolved[:10] if resolved else "en"


def _resolve_org_id(request: Request) -> str | None:
    org = getattr(request, "organization", None)
    return str(org.id) if org is not None else None


def _circuit_open_response() -> Response:
    retry_after = str(openai_circuit_breaker.recovery_timeout)
    return Response(
        {
            "error": "AI service temporarily unavailable",
            "retry_after": openai_circuit_breaker.recovery_timeout,
        },
        status=503,
        headers={"Retry-After": retry_after},
    )


@extend_schema(
    request={
        "application/json": {
            "type": "object",
            "properties": {
                "description": {"type": "string"},
                "lang": {"type": "string", "default": "en"},
            },
            "required": ["description"],
        }
    },
    responses={
        200: {
            "type": "object",
            "properties": {
                "en": {"type": "object"},
                "es": {"type": "object"},
                "fr": {"type": "object"},
            },
        },
        400: {"type": "object"},
        502: {"type": "object"},
        503: {"type": "object"},
    },
)
@api_view(["POST"])
@permission_classes([IsAuthenticated])
@throttle_classes([AIAssistRateThrottle, BurstRateThrottle])
def suggest_task(request: Request) -> Response:
    """Generate formal EN/ES/FR translations for a task description."""
    try:
        description = _extract_string_field(request.data, "description")
        lang = _resolve_lang_param(request)
    except ValueError as exc:
        return Response({"error": str(exc)}, status=400)

    if not description:
        return Response({"error": "Description is required"}, status=400)

    try:
        org_id = _resolve_org_id(request)
        call_kwargs = {"organization_id": org_id} if org_id else {}
        result = _ai_service.suggest_task_translations(
            user_id=str(request.user.id), lang=lang, user_input=description, **call_kwargs
        )
        return Response(result)
    except ValueError as exc:
        logger.warning("Input validation rejected on suggest_task: %s", exc)
        return Response({"error": str(exc)}, status=400)
    except CircuitOpenError:
        return _circuit_open_response()
    except Exception as exc:
        logger.error("Translation failed: %s", exc)
        return Response(
            {"error": "AI service temporarily unavailable"},
            status=502,
        )


@extend_schema(
    request={
        "application/json": {
            "type": "object",
            "properties": {
                "prompt_text": {"type": "string"},
                "lang": {"type": "string", "default": "en"},
            },
            "required": ["prompt_text"],
        }
    },
    responses={
        200: {
            "type": "object",
            "properties": {
                "score": {"type": "integer"},
                "improvements": {"type": "array"},
                "analysis": {"type": "string"},
            },
        },
        400: {"type": "object"},
        502: {"type": "object"},
        503: {"type": "object"},
    },
)
@api_view(["POST"])
@permission_classes([IsAuthenticated])
@throttle_classes([AIAssistRateThrottle, BurstRateThrottle])
def evaluate_quality(request: Request) -> Response:
    """Evaluate a prompt for clarity, constraints, and edge-case handling."""
    try:
        prompt_text = _extract_string_field(request.data, "prompt_text", "prompt")
        lang = _resolve_lang_param(request)
    except ValueError as exc:
        return Response({"error": str(exc)}, status=400)

    if not prompt_text:
        return Response({"error": "Prompt text is required"}, status=400)

    try:
        org_id = _resolve_org_id(request)
        call_kwargs = {"organization_id": org_id} if org_id else {}
        result = _ai_service.evaluate_prompt_quality(
            user_id=str(request.user.id), lang=lang, user_input=prompt_text, **call_kwargs
        )
        return Response(result)
    except ValueError as exc:
        logger.warning("Input validation rejected on evaluate_quality: %s", exc)
        return Response({"error": str(exc)}, status=400)
    except CircuitOpenError:
        return _circuit_open_response()
    except Exception as exc:
        logger.error("Quality evaluation failed: %s", exc)
        return Response(
            {"error": "AI service temporarily unavailable"},
            status=502,
        )


@extend_schema(
    request={
        "application/json": {
            "type": "object",
            "properties": {
                "code_snippet": {"type": "string"},
                "lang": {"type": "string", "default": "en"},
            },
            "required": ["code_snippet"],
        }
    },
    responses={
        200: {
            "type": "object",
            "properties": {
                "instruction": {"type": "string"},
                "input": {"type": "string"},
                "output": {"type": "string"},
                "metadata": {"type": "object"},
            },
        },
        400: {"type": "object"},
        502: {"type": "object"},
        503: {"type": "object"},
    },
)
@api_view(["POST"])
@permission_classes([IsAuthenticated])
@throttle_classes([AIAssistRateThrottle, BurstRateThrottle])
def generate_test_cases(request: Request) -> Response:
    """Generate RLHF-style pytest unit tests for a Python code snippet."""
    try:
        code_snippet = _extract_string_field(request.data, "code_snippet", "task_description")
        lang = _resolve_lang_param(request)
    except ValueError as exc:
        return Response({"error": str(exc)}, status=400)

    if not code_snippet:
        return Response({"error": "Code snippet is required"}, status=400)

    try:
        org_id = _resolve_org_id(request)
        call_kwargs = {"organization_id": org_id} if org_id else {}
        result = _ai_service.generate_rlhf_test_cases(
            user_id=str(request.user.id), lang=lang, user_input=code_snippet, **call_kwargs
        )
        return Response(result)
    except ValueError as exc:
        logger.warning("Input validation rejected on generate_test_cases: %s", exc)
        return Response({"error": str(exc)}, status=400)
    except CircuitOpenError:
        return _circuit_open_response()
    except Exception as exc:
        logger.error("Test generation failed: %s", exc)
        return Response(
            {"error": "AI service temporarily unavailable"},
            status=502,
        )
