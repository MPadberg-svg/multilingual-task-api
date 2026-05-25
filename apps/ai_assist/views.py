"""AI Assist API views.

Provides three authenticated, throttled endpoints for OpenAI-powered
operations: task translation suggestions, prompt quality evaluation,
and RLHF-style test case generation.

All endpoints:
* Require authentication (``IsAuthenticated``).
* Are rate-limited by ``AIAssistRateThrottle`` (20/hour) and
  ``BurstRateThrottle`` (5/min).
* Return ``502 Bad Gateway`` if the upstream AI service fails.
"""

import logging

from drf_spectacular.utils import extend_schema
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from apps.ai_assist.services import _ai_service
from apps.core.throttling import AIAssistRateThrottle, BurstRateThrottle

logger = logging.getLogger(__name__)


@extend_schema(
    request={
        "application/json": {
            "schema": {
                "type": "object",
                "properties": {
                    "description": {"type": "string"},
                    "lang": {"type": "string", "default": "en"},
                },
                "required": ["description"],
            }
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
    },
)
@api_view(["POST"])
@permission_classes([IsAuthenticated])
@throttle_classes([AIAssistRateThrottle, BurstRateThrottle])
def suggest_task(request):
    """Generate formal EN/ES/FR translations for a task description.

    Args:
        request: DRF Request with JSON body containing ``description``.

    Returns:
        Response with translated titles and descriptions, or 400/502.
    """
    description = request.data.get("description", "")
    lang = request.data.get("lang", "en")

    if not description or len(description.strip()) == 0:
        return Response({"error": "Description is required"}, status=400)

    try:
        # Aligned with services.py signature requirements
        result = _ai_service.suggest_task_translations(
            user_id=str(request.user.id), lang=lang, user_input=description
        )
        return Response(result)
    except ValueError as exc:
        logger.warning("Input validation rejected: %s", exc)
        return Response({"error": str(exc)}, status=400)
    except Exception as exc:
        logger.error("Translation failed: %s", exc)
        return Response(
            {"error": "AI service temporarily unavailable"},
            status=502,
        )


@extend_schema(
    request={
        "application/json": {
            "schema": {
                "type": "object",
                "properties": {
                    "prompt_text": {"type": "string"},
                    "lang": {"type": "string", "default": "en"},
                },
                "required": ["prompt_text"],
            }
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
    },
)
@api_view(["POST"])
@permission_classes([IsAuthenticated])
@throttle_classes([AIAssistRateThrottle, BurstRateThrottle])
def evaluate_quality(request):
    """Evaluate a prompt for clarity, constraints, and edge-case handling.

    Args:
        request: DRF Request with JSON body containing ``prompt_text``.

    Returns:
        Response with score, improvements list, and analysis, or 400/502.
    """
    prompt_text = request.data.get("prompt_text") or request.data.get("prompt", "")
    lang = request.data.get("lang", "en")

    if not prompt_text or len(prompt_text.strip()) == 0:
        return Response({"error": "Prompt text is required"}, status=400)

    try:
        # Aligned with services.py signature requirements
        result = _ai_service.evaluate_prompt_quality(
            user_id=str(request.user.id), lang=lang, user_input=prompt_text
        )
        return Response(result)
    except Exception as exc:
        logger.error("Quality evaluation failed: %s", exc)
        return Response(
            {"error": "AI service temporarily unavailable"},
            status=502,
        )


@extend_schema(
    request={
        "application/json": {
            "schema": {
                "type": "object",
                "properties": {
                    "code_snippet": {"type": "string"},
                    "lang": {"type": "string", "default": "en"},
                },
                "required": ["code_snippet"],
            }
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
    },
)
@api_view(["POST"])
@permission_classes([IsAuthenticated])
@throttle_classes([AIAssistRateThrottle, BurstRateThrottle])
def generate_test_cases(request):
    """Generate RLHF-style pytest unit tests for a Python code snippet.

    Args:
        request: DRF Request with JSON body containing ``code_snippet``.

    Returns:
        Response with instruction, input, output, and metadata, or 400/502.
    """
    code_snippet = (
        request.data.get("code_snippet")
        or request.data.get("task_description", "")
    )
    lang = request.data.get("lang", "en")

    if not code_snippet or len(code_snippet.strip()) == 0:
        return Response({"error": "Code snippet is required"}, status=400)

    try:
        # Aligned with services.py signature requirements
        result = _ai_service.generate_rlhf_test_cases(
            user_id=str(request.user.id), lang=lang, user_input=code_snippet
        )
        return Response(result)
    except Exception as exc:
        logger.error("Test generation failed: %s", exc)
        return Response(
            {"error": "AI service temporarily unavailable"},
            status=502,
        )
