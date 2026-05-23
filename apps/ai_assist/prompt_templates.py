"""AI prompt templates for multilingual task assistance.

Provides:
    - Versioned prompt constants (immutable).
    - ``PromptTemplateManager``: Renders prompts with variable substitution
      and version tracking.
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


class PromptTemplateManager:
    """Renders versioned prompt templates with variable substitution.

    Attributes:
        templates (dict): Mapping of template names to (prompt, version) tuples.
    """

    def __init__(self) -> None:
        """Initialise the template registry."""
        self.templates: dict[str, tuple[str, str]] = {
            "task_translation": (TASK_TRANSLATION_PROMPT, PROMPT_VERSION_TRANSLATION),
            "prompt_evaluation": (QUALITY_EVALUATION_PROMPT, PROMPT_VERSION_QUALITY),
            "rlhf_generation": (TEST_CASE_GENERATION_PROMPT, PROMPT_VERSION_TEST),
        }

    def render(self, template_name: str, **kwargs: str) -> str:
        """Render a prompt template with variable substitution.

        Args:
            template_name: Key in the template registry.
            **kwargs: Variables to substitute into the prompt.

        Returns:
            Rendered prompt string.

        Raises:
            KeyError: If ``template_name`` is not registered.
        """
        if template_name not in self.templates:
            raise KeyError(f"Unknown template: {template_name}")

        prompt, _version = self.templates[template_name]

        # Simple substitution for known placeholders
        rendered = prompt
        for key, value in kwargs.items():
            placeholder = f"{{{key}}}"
            if placeholder in rendered:
                rendered = rendered.replace(placeholder, str(value))

        return rendered

    def get_version(self, template_name: str) -> str:
        """Return the version string for a template.

        Args:
            template_name: Key in the template registry.

        Returns:
            Version string (e.g. ``v1.2.0``).

        Raises:
            KeyError: If ``template_name`` is not registered.
        """
        if template_name not in self.templates:
            raise KeyError(f"Unknown template: {template_name}")
        return self.templates[template_name][1]
