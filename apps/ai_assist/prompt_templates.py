"""AI prompt templates for multilingual task assistance.

All prompts are declared as Final[str] constants to prevent runtime mutation.
"""
from typing import Final

# =============================================================================
# Prompt Versions
# =============================================================================
PROMPT_VERSION_TRANSLATION: Final[str] = "v1.2.0"
PROMPT_VERSION_QUALITY: Final[str] = "v2.0.1"
PROMPT_VERSION_TEST: Final[str] = "v1.0.3"

# =============================================================================
# Task Translation Prompt
# =============================================================================
TASK_TRANSLATION_PROMPT: Final[str] = (
    "You are a professional translator for AI annotation platforms. "
    "Given a task description, generate formal (usted/vous register) "
    "translations in English, Spanish, and French. "
    "Return ONLY valid JSON: "
    '{"en":{"title":"...","description":"..."},"es":{...},"fr":{...}}. '
    "Ensure descriptions maintain technical accuracy and formal tone."
)

# =============================================================================
# Quality Evaluation Prompt
# =============================================================================
QUALITY_EVALUATION_PROMPT: Final[str] = (
    "You are a prompt engineering expert. "
    "Evaluate the following prompt for clarity, constraints specification, "
    "and edge case handling. Score 0-100. "
    "Return ONLY valid JSON: "
    '{"score":integer,"improvements":[string,...],"analysis":"string"}. '
    "Be critical and specific."
)

# =============================================================================
# Test Case Generation Prompt (RLHF)
# =============================================================================
TEST_CASE_GENERATION_PROMPT: Final[str] = (
    "You are a software testing expert. "
    "Given a code snippet, generate comprehensive pytest unit tests "
    "including edge cases. "
    "Return ONLY valid JSON: "
    '{"instruction":"...","input":"...","output":"...",'
    '"metadata":{"language":"python","framework":"pytest",'
    '"edge_cases":["...",...]}}. '
    "Ensure tests cover boundary conditions and error paths."
)