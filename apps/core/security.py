"""Security utilities for input validation and sanitization.

Provides ``InputValidator`` with pattern-based detection for SQL injection,
script injection, and dangerous code execution, plus Unicode-preserving
text sanitization and HTML escaping.

Example:
    >>> from apps.core.security import InputValidator
    >>> InputValidator.full_sanitize("<script>alert(1)</script>")
    ValueError: Security violation: ...
"""

from __future__ import annotations

import html
import logging
import re
import unicodedata

logger = logging.getLogger(__name__)


class InputValidator:
    """Validates and sanitizes untrusted user input.

    Attributes:
        SQL_INJECTION_PATTERNS (list): Regex patterns matching common SQLi.
        SCRIPT_PATTERNS (list): Regex patterns matching XSS / script tags.
        DANGEROUS_CODE_PATTERNS (list): Regex patterns matching dangerous
            Python code constructs (eval, exec, os.system, etc.).
    """

    # Patterns target structural SQLi markers, not lone English words like
    # "select" or "update" that appear in normal user prose. All DB access in
    # this project goes through the ORM with parameterised binding, so this
    # is defense-in-depth for LLM-bound and stored input.
    SQL_INJECTION_PATTERNS = [
        r"\bUNION\s+(ALL\s+)?SELECT\b",
        r"\bDROP\s+(TABLE|DATABASE|SCHEMA)\b",
        r"\bINSERT\s+INTO\b",
        r"\bDELETE\s+FROM\b",
        r"\bUPDATE\s+\w+\s+SET\b",
        r"\bSELECT\s+.+\s+FROM\b",
        r";\s*(SELECT|INSERT|UPDATE|DELETE|DROP|EXEC|EXECUTE)\b",
        r"'\s*(OR|AND)\s+\d+\s*=\s*\d+",
        r"\bWAITFOR\s+DELAY\b",
        r"--\s*$",
        r";--",
        r"/\*.*?\*/",
        r"\bxp_\w+",
        r"\bsp_executesql\b",
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
        """Strip control/invisible characters while preserving full UTF-8 multilingual text.

        Normalizes line endings, NFC-normalizes Unicode, removes null bytes and
        Unicode control/surrogate characters (category ``C*`` except ``\\n`` and
        ``\\t``), and enforces length limits. Preserves French ligatures (``œ``),
        currency symbols (``€``), CJK, Arabic, Cyrillic, and accented scripts.

        Args:
            value: Raw input string.
            max_length: Maximum permitted length (default 10 000).

        Returns:
            Cleaned UTF-8 string.

        Raises:
            ValueError: If ``value`` exceeds ``max_length``.
        """
        if not isinstance(value, str):
            value = str(value)
        if len(value) > max_length:
            raise ValueError(f"Input exceeds maximum length of {max_length}")

        normalized = unicodedata.normalize("NFC", value.replace("\r\n", "\n").replace("\r", "\n"))
        cleaned = "".join(
            ch
            for ch in normalized
            if ch in ("\n", "\t") or not unicodedata.category(ch).startswith("C")
        )
        return cleaned.strip()

    @classmethod
    def detect_sqli(cls, value: str) -> tuple[bool, str]:
        """Scan input for SQL injection patterns."""
        for pattern in cls.SQL_INJECTION_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                return True, f"SQL injection pattern detected: {pattern}"
        return False, ""

    @classmethod
    def detect_xss(cls, value: str) -> tuple[bool, str]:
        """Scan input for script injection/XSS patterns."""
        for pattern in cls.SCRIPT_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE | re.DOTALL):
                return True, f"XSS pattern detected: {pattern}"
        return False, ""

    @classmethod
    def detect_injection(cls, value: str) -> tuple[bool, str]:
        """Scan input for SQLi or script-injection patterns."""
        is_sqli, reason = cls.detect_sqli(value)
        if is_sqli:
            return True, reason

        is_xss, reason = cls.detect_xss(value)
        if is_xss:
            return True, reason

        return False, ""

    @classmethod
    def validate_code_input(cls, code: str) -> tuple[bool, str]:
        """Scan code string for dangerous execution patterns."""
        for pattern in cls.DANGEROUS_CODE_PATTERNS:
            if re.search(pattern, code, re.IGNORECASE):
                return True, f"Dangerous code pattern blocked: {pattern}"
        return False, ""

    @classmethod
    def full_sanitize(cls, value: str, max_length: int = 10000) -> str:
        """Combined validation: detect injection then HTML-escape."""
        is_dangerous, reason = cls.detect_injection(value)
        if is_dangerous:
            raise ValueError(f"Security violation: {reason}")
        return cls.sanitize_html(value, max_length)
