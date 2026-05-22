"""Tests for RequestTimingMiddleware."""

import contextlib
import logging
from unittest.mock import MagicMock

import pytest
from django.db import connection
from django.http import HttpResponse
from django.test import RequestFactory
from django.test.utils import CaptureQueriesContext

from apps.analytics.middleware import RequestTimingMiddleware


class TestRequestTimingMiddleware:
    """Tests for the request timing analytics middleware."""

    def setup_method(self):
        self.factory = RequestFactory()
        self.get_response = MagicMock(return_value=HttpResponse("OK", status=200))
        self.middleware = RequestTimingMiddleware(self.get_response)

    def test_middleware_calls_get_response(self):
        """Middleware must delegate to the wrapped get_response callable."""
        request = self.factory.get("/api/v1/tasks/")
        self.middleware(request)
        assert self.get_response.called

    def test_middleware_returns_response(self):
        """Middleware must return the response object from get_response."""
        request = self.factory.get("/api/v1/health/")
        response = self.middleware(request)
        assert response is not None
        assert response.status_code == 200

    @pytest.mark.django_db
    def test_middleware_does_not_add_db_queries(self):
        """RequestTimingMiddleware must have 0 DB queries — per project spec."""
        request = self.factory.get("/api/v1/tasks/")
        with CaptureQueriesContext(connection) as ctx:
            self.middleware(request)
        assert len(ctx.captured_queries) == 0, (
            f"Middleware made {len(ctx.captured_queries)} DB queries — expected 0"
        )

    def test_middleware_logs_request_timing(self):
        """Middleware must emit a structured 'request_timing' log record."""
        request = self.factory.get("/api/v1/tasks/")
        response = HttpResponse("OK", status=200)
        self.get_response.return_value = response

        with self._capture_log_records("apps.analytics.middleware") as records:
            self.middleware(request)

        timing_logs = [r for r in records if r.message == "request_timing"]
        assert len(timing_logs) == 1, (
            f"Expected exactly 1 'request_timing' log, got {len(timing_logs)}"
        )
        log = timing_logs[0]
        assert hasattr(log, "method") and log.method == "GET"
        assert hasattr(log, "path") and log.path == "/api/v1/tasks/"
        assert hasattr(log, "status_code") and log.status_code == 200
        assert hasattr(log, "duration_ms") and isinstance(log.duration_ms, float)

    def test_middleware_handles_exception_gracefully(self):
        """Middleware must re-raise exceptions without swallowing them."""
        request = self.factory.get("/api/v1/tasks/")
        self.get_response.side_effect = RuntimeError("Downstream failure")

        with pytest.raises(RuntimeError, match="Downstream failure"):
            self.middleware(request)

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    @contextlib.contextmanager
    def _capture_log_records(logger_name: str):
        """Capture all log records emitted by the named logger."""
        logger = logging.getLogger(logger_name)
        original_level = logger.level
        logger.setLevel(logging.DEBUG)

        records = []
        handler = logging.Handler()
        handler.emit = lambda record: records.append(record)
        logger.addHandler(handler)

        try:
            yield records
        finally:
            logger.removeHandler(handler)
            logger.setLevel(original_level)