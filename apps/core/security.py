"""Security utilities for input validation and sanitization.

Provides ``InputValidator`` with pattern-based detection for SQL injection,
script injection, and dangerous code execution, plus HTML escaping.

Example:
    >>> from apps.core.security import InputValidator
    >>> InputValidator.full_sanitize("<script>alert(1)</script>")
    ValueError: Security violation: ...
"""

import html
import logging
import re

logger = logging.getLogger(__name__)


class InputValidator:
    """Validates and sanitizes untrusted user input.

    Attributes:
        SQL_INJECTION_PATTERNS (list): Regex patterns matching common SQLi.
        SCRIPT_PATTERNS (list): Regex patterns matching XSS / script tags.
        DANGEROUS_CODE_PATTERNS (list): Regex patterns matching dangerous
            Python code constructs (eval, exec, os.system, etc.).
    """

    SQL_INJECTION_PATTERNS = [
        r"\bDROP\b",
        r"\bUNION\b",
        r"\bSELECT\b",
        r"\bINSERT\b",
        r"\bDELETE\b",
        r"\bUPDATE\b",
        r"\bEXEC\b",
        r"\bEXECUTE\b",
        r"\bWAITFOR\b",
        r"--\s*$",
        r";--",
        r"/\*.*?\*/",
        r"\bxp_",
        r"\bsp_",
    ]

    SCRIPT_PATTERNS = [
        r"<script[^>]*>.*?",
        r"javascript:",
        r"\bon\w+\s*=",
        r"\bonerror\s*=",
        r"\bonload\s*=",
        r"\beval\s*\(",
        r"\bexpression\s*\(",
    ]

    DANGEROUS_CODE_PATTERNS = [
        r"\beval\s*\(",
        r"\bexec\s*\(",
        r"\bos\.system\s*\(",
        r"\bsubprocess\b",
        r"\b__import__\b",
        r"\bcompile\s*\(",
    ]

    @staticmethod
    def sanitize_html(value: str, max_length: int = 10000) -> str:
        """Escape HTML entities and enforce length limits.

        Args:
            value: Raw input string.
            max_length: Maximum permitted length (default 10 000).

        Returns:
            HTML-escaped string.

        Raises:
            ValueError: If ``value`` exceeds ``max_length``.
        """
        if not isinstance(value, str):
            value = str(value)
        if len(value) > max_length:
            raise ValueError(f"Input exceeds maximum length of {max_length}")
        return html.escape(value)

    @staticmethod
    def sanitize_string(value: str, max_length: int = 10000) -> str:
        """Strip dangerous characters and enforce length limits.

        Unlike ``sanitize_html``, this does NOT escape HTML entities.
        It removes null bytes, control characters, and enforces length.
        Use this for plain text inputs before sending to LLMs.

        Args:
            value: Raw input string.
            max_length: Maximum permitted length (default 10 000).

        Returns:
            Cleaned string.

        Raises:
            ValueError: If ``value`` exceeds ``max_length``.
        """
        if not isinstance(value, str):
            value = str(value)
        if len(value) > max_length:
            raise ValueError(f"Input exceeds maximum length of {max_length}")
        # Remove null bytes and most control characters (keep tab, newline, space)
        cleaned = "".join(
            ch
            for ch in value
            if ch == "\n"
            or ch == "\t"
            or (ch >= " " and ch <= "~")
            or ch
            in "¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ"
        )
        return cleaned.strip()

    @classmethod
    def detect_sqli(cls, value: str) -> tuple[bool, str]:
        """Scan input for SQL injection patterns.

        Args:
            value: Raw input string.

        Returns:
            Tuple of ``(is_dangerous, reason)``.
        """
        for pattern in cls.SQL_INJECTION_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                return True, f"SQL injection pattern detected: {pattern}"
        return False, ""

    @classmethod
    def detect_xss(cls, value: str) -> tuple[bool, str]:
        """Scan input for script injection/XSS patterns.

        Args:
            value: Raw input string.

        Returns:
            Tuple of ``(is_dangerous, reason)``.
        """
        for pattern in cls.SCRIPT_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE | re.DOTALL):
                return True, f"XSS pattern detected: {pattern}"
        return False, ""

    @classmethod
    def detect_injection(cls, value: str) -> tuple[bool, str]:
        """Scan input for SQLi or script-injection patterns.

        Args:
            value: Raw input string.

        Returns:
            Tuple of ``(is_dangerous, reason)``.
        """
        is_sqli, reason = cls.detect_sqli(value)
        if is_sqli:
            return True, reason

        is_xss, reason = cls.detect_xss(value)
        if is_xss:
            return True, reason

        return False, ""

    @classmethod
    def validate_code_input(cls, code: str) -> tuple[bool, str]:
        """Scan code string for dangerous execution patterns.

        Args:
            code: Raw code string.

        Returns:
            Tuple of ``(is_dangerous, reason)``.
        """
        for pattern in cls.DANGEROUS_CODE_PATTERNS:
            if re.search(pattern, code, re.IGNORECASE):
                return True, f"Dangerous code pattern blocked: {pattern}"
        return False, ""

    @classmethod
    def full_sanitize(cls, value: str, max_length: int = 10000) -> str:
        """Combined validation: detect injection then HTML-escape.

        Args:
            value: Raw input string.
            max_length: Maximum permitted length.

        Returns:
            Sanitized, HTML-escaped string.

        Raises:
            ValueError: If injection detected or length exceeded.
        """
        is_dangerous, reason = cls.detect_injection(value)
        if is_dangerous:
            raise ValueError(f"Security violation: {reason}")
        return cls.sanitize_html(value, max_length)
