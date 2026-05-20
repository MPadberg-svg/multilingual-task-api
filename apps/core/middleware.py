"""Core middleware for multilingual-task-api.

Provides language resolution and correlation ID propagation with
thread-safe implementations to prevent request leakage across threads.
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from django.conf import settings
from django.http import HttpRequest, HttpResponse
from django.utils import translation
from django.utils.deprecation import MiddlewareMixin


class LanguageResolutionMiddleware(MiddlewareMixin):
    """Resolve and activate the request language with thread-safe cleanup.

    Resolution order:
        1. Query parameter: ?lang=<code>
        2. Accept-Language header (with quality value parsing and locale normalization)
        3. Default from settings.PARLER_LANGUAGES

    Supported languages are validated against settings.PARLER_LANGUAGES.
    Translation is activated for the request lifecycle and explicitly
    deactivated afterward to prevent thread leakage in threaded environments.
    """

    # Regex to strip locale variants (e.g., "en-US" → "en")
    _LOCALE_VARIANT_RE: re.Pattern[str] = re.compile(r"^([a-zA-Z]{2})(?:-[a-zA-Z]{2})?$")

    # Regex to parse Accept-Language quality values
    _ACCEPT_LANGUAGE_RE: re.Pattern[str] = re.compile(
        r"([a-zA-Z]{1,8}(?:-[a-zA-Z0-9]{1,8})?)\s*(?:;q\s*=\s*([0-9.]+))?"
    )

    def process_request(self, request: HttpRequest) -> None:
        """Resolve language, activate translation, and attach to request."""
        resolved_code: str = self._resolve_language(request)
        translation.activate(resolved_code)
        request.language = resolved_code  # type: ignore[attr-defined]

    def process_response(
        self, request: HttpRequest, response: HttpResponse
    ) -> HttpResponse:
        """Set Content-Language header and deactivate translation."""
        resolved_code: str = getattr(request, "language", settings.LANGUAGE_CODE)
        response["Content-Language"] = resolved_code
        translation.deactivate()
        return response

    def _resolve_language(self, request: HttpRequest) -> str:
        """Apply resolution hierarchy: query param > Accept-Language > default."""
        supported_codes: set[str] = self._get_supported_codes()

        # 1. Query parameter (highest priority)
        query_lang: str | None = request.GET.get("lang")
        if query_lang:
            normalized: str | None = self._normalize_code(query_lang)
            if normalized and normalized in supported_codes:
                return normalized

        # 2. Accept-Language header with quality value parsing
        accept_header: str | None = request.META.get("HTTP_ACCEPT_LANGUAGE")
        if accept_header:
            parsed: list[tuple[str, float]] = self._parse_accept_language(accept_header)
            for code, _quality in parsed:
                normalized = self._normalize_code(code)
                if normalized and normalized in supported_codes:
                    return normalized

        # 3. Default fallback
        return self._get_default_code()

    @staticmethod
    def _get_supported_codes() -> set[str]:
        """Extract supported language codes from PARLER_LANGUAGES."""
        parler_conf: dict[str, Any] = settings.PARLER_LANGUAGES
        site_languages: list[dict[str, str]] = parler_conf.get("1", [])
        return {entry["code"] for entry in site_languages}

    @staticmethod
    def _get_default_code() -> str:
        """Return the default language code from PARLER_LANGUAGES."""
        parler_conf: dict[str, Any] = settings.PARLER_LANGUAGES
        default_conf: dict[str, Any] = parler_conf.get("default", {})
        return default_conf.get("code", "en")

    @classmethod
    def _normalize_code(cls, raw_code: str) -> str | None:
        """Normalize locale variants (e.g., 'en-US' → 'en')."""
        raw_code = raw_code.strip().lower()
        match: re.Match[str] | None = cls._LOCALE_VARIANT_RE.match(raw_code)
        if match:
            return match.group(1)
        return None

    @classmethod
    def _parse_accept_language(cls, header: str) -> list[tuple[str, float]]:
        """Parse Accept-Language header with quality values.

        Returns a list of (language_code, quality) tuples sorted by
        descending quality. Handles locale variants and invalid q values.
        """
        entries: list[tuple[str, float]] = []
        for match in cls._ACCEPT_LANGUAGE_RE.finditer(header):
            code: str = match.group(1).strip().lower()
            q_str: str = match.group(2) if match.group(2) else "1.0"
            try:
                quality: float = float(q_str)
                if not 0.0 <= quality <= 1.0:
                    quality = 0.0
            except ValueError:
                quality = 0.0
            entries.append((code, quality))

        # Sort by descending quality
        entries.sort(key=lambda x: x[1], reverse=True)
        return entries


class CorrelationIdMiddleware(MiddlewareMixin):
    """Propagate correlation IDs across requests for distributed tracing.

    Checks the X-Correlation-ID header on incoming requests and generates
    a UUID4 if absent. Attaches the ID to the request object and echoes it
    back in the response headers. Thread-safe via MiddlewareMixin.
    """

    _HEADER_NAME: str = "X-Correlation-ID"

    def process_request(self, request: HttpRequest) -> None:
        """Extract or generate correlation ID and attach to request."""
        correlation_id: str = request.headers.get(self._HEADER_NAME, "")
        if not correlation_id:
            correlation_id = str(uuid.uuid4())
        request.correlation_id = correlation_id  # type: ignore[attr-defined]

    def process_response(
        self, request: HttpRequest, response: HttpResponse
    ) -> HttpResponse:
        """Echo correlation ID back in response headers."""
        correlation_id: str = getattr(request, "correlation_id", str(uuid.uuid4()))
        response[self._HEADER_NAME] = correlation_id
        return response