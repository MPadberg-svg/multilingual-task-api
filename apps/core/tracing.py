"""W3C Trace Context propagation and OpenTelemetry OTLP/HTTP JSON span exporter.

Implements the W3C Trace Context specification (``traceparent`` header
``00-<trace_id_32hex>-<span_id_16hex>-<flags_2hex>``) and exports completed spans
using the vendor-neutral OpenTelemetry ``ExportTraceServiceRequest`` JSON wire
format over ``http.client`` — adding zero third-party protobuf/gRPC dependencies.

Correlates spans across four execution boundaries:
    1. Django HTTP requests (``CorrelationIdMiddleware``)
    2. Celery async worker tasks (``before_task_publish`` / ``task_prerun`` / ``task_postrun``)
    3. OpenAI chat completion calls (``AIService._call_llm``)
    4. Outbound signed webhook deliveries (``deliver_webhook_sync``)
"""

from __future__ import annotations

import collections
import contextvars
import http.client
import json
import logging
import re
import secrets
import ssl
import threading
import time
import urllib.parse
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

from django.conf import settings

logger = logging.getLogger(__name__)

_TRACEPARENT_RE = re.compile(
    r"^(?P<version>[0-9a-f]{2})-(?P<trace_id>[0-9a-f]{32})-"
    r"(?P<span_id>[0-9a-f]{16})-(?P<flags>[0-9a-f]{2})$"
)
_ZERO_TRACE_ID = "0" * 32
_ZERO_SPAN_ID = "0" * 16

_SPAN_KIND_MAP = {
    "INTERNAL": 1,
    "SERVER": 2,
    "CLIENT": 3,
    "PRODUCER": 4,
    "CONSUMER": 5,
}

OTLP_EXPORT_TIMEOUT_SECONDS: float = 1.5
MAX_BUFFERED_SPANS: int = 200


@dataclass(frozen=True)
class TraceContext:
    """Immutable W3C Trace Context state."""

    trace_id: str
    span_id: str
    sampled: bool = True

    @property
    def traceparent(self) -> str:
        flags = "01" if self.sampled else "00"
        return f"00-{self.trace_id}-{self.span_id}-{flags}"


@dataclass
class SpanRecord:
    """Completed or in-flight distributed trace span."""

    name: str
    trace_id: str
    span_id: str
    parent_span_id: str | None
    kind: str
    start_time_unix_nano: int
    end_time_unix_nano: int = 0
    status_code: str = "OK"
    status_message: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)

    def set_attribute(self, key: str, value: Any) -> None:
        self.attributes[key] = value

    def set_error(self, message: str) -> None:
        self.status_code = "ERROR"
        self.status_message = message[:300]

    @property
    def traceparent(self) -> str:
        return f"00-{self.trace_id}-{self.span_id}-01"


_CURRENT_TRACE: contextvars.ContextVar[TraceContext | None] = contextvars.ContextVar(
    "_CURRENT_TRACE", default=None
)
_RECENT_SPANS: collections.deque[SpanRecord] = collections.deque(maxlen=MAX_BUFFERED_SPANS)
_BUFFER_LOCK = threading.Lock()


def generate_trace_id() -> str:
    """Generate a non-zero 16-byte (32-hex) W3C trace identifier."""
    tid = secrets.token_hex(16)
    return tid if tid != _ZERO_TRACE_ID else "1" + ("0" * 31)


def generate_span_id() -> str:
    """Generate a non-zero 8-byte (16-hex) W3C span identifier."""
    sid = secrets.token_hex(8)
    return sid if sid != _ZERO_SPAN_ID else "1" + ("0" * 15)


def parse_traceparent(raw_header: str | None) -> TraceContext | None:
    """Parse and validate an incoming W3C ``traceparent`` header."""
    if not raw_header:
        return None
    cleaned = raw_header.strip().lower()
    match = _TRACEPARENT_RE.match(cleaned)
    if not match:
        return None
    version = match.group("version")
    trace_id = match.group("trace_id")
    span_id = match.group("span_id")
    flags = int(match.group("flags"), 16)
    if version == "ff" or trace_id == _ZERO_TRACE_ID or span_id == _ZERO_SPAN_ID:
        return None
    return TraceContext(trace_id=trace_id, span_id=span_id, sampled=bool(flags & 0x01))


def get_current_trace_context() -> TraceContext | None:
    """Return the active ``TraceContext`` bound to the current execution context."""
    return _CURRENT_TRACE.get()


def get_current_traceparent() -> str | None:
    """Return the active W3C ``traceparent`` string if a trace is active."""
    ctx = _CURRENT_TRACE.get()
    return ctx.traceparent if ctx is not None else None


def get_recent_spans() -> list[SpanRecord]:
    """Return a snapshot of recently recorded spans (for diagnostics and testing)."""
    with _BUFFER_LOCK:
        return list(_RECENT_SPANS)


def clear_recent_spans() -> None:
    """Clear the in-memory span ring buffer."""
    with _BUFFER_LOCK:
        _RECENT_SPANS.clear()


def _otel_attr_value(val: Any) -> dict[str, Any]:
    if isinstance(val, bool):
        return {"boolValue": val}
    if isinstance(val, int):
        return {"intValue": str(val)}
    if isinstance(val, float):
        return {"doubleValue": val}
    return {"stringValue": str(val)}


def build_otlp_payload(span: SpanRecord) -> dict[str, Any]:
    """Serialize ``span`` into an OpenTelemetry ``ExportTraceServiceRequest`` JSON dict."""
    service_name = getattr(settings, "OTEL_SERVICE_NAME", "multilingual-task-api")
    otel_status = 2 if span.status_code == "ERROR" else 1
    span_dict: dict[str, Any] = {
        "traceId": span.trace_id,
        "spanId": span.span_id,
        "name": span.name,
        "kind": _SPAN_KIND_MAP.get(span.kind.upper(), 1),
        "startTimeUnixNano": str(span.start_time_unix_nano),
        "endTimeUnixNano": str(span.end_time_unix_nano),
        "attributes": [
            {"key": k, "value": _otel_attr_value(v)}
            for k, v in span.attributes.items()
            if v is not None
        ],
        "status": {"code": otel_status, "message": span.status_message},
    }
    if span.parent_span_id:
        span_dict["parentSpanId"] = span.parent_span_id

    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": str(service_name)}},
                        {"key": "service.version", "value": {"stringValue": "1.3.0"}},
                    ]
                },
                "scopeSpans": [
                    {
                        "scope": {"name": "apps.core.tracing", "version": "1.3.0"},
                        "spans": [span_dict],
                    }
                ],
            }
        ]
    }


def _send_otlp_http(endpoint_url: str, payload: dict[str, Any]) -> None:
    """Best-effort, bounded-timeout OTLP/HTTP JSON export (never raises)."""
    try:
        parsed = urllib.parse.urlparse(endpoint_url.strip())
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"} or not parsed.hostname:
            return
        path = parsed.path or "/v1/traces"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers: dict[str, str] = {"Content-Type": "application/json"}
        raw_headers = str(getattr(settings, "OTEL_EXPORTER_OTLP_HEADERS", "") or "").strip()
        if raw_headers:
            for pair in raw_headers.split(","):
                if "=" in pair:
                    hk, hv = pair.split("=", 1)
                    if hk.strip():
                        headers[hk.strip()] = hv.strip()

        conn: http.client.HTTPConnection
        if scheme == "https":
            conn = http.client.HTTPSConnection(
                parsed.hostname,
                port=parsed.port or 443,
                timeout=OTLP_EXPORT_TIMEOUT_SECONDS,
                context=ssl.create_default_context(),
            )
        else:
            conn = http.client.HTTPConnection(
                parsed.hostname,
                port=parsed.port or 80,
                timeout=OTLP_EXPORT_TIMEOUT_SECONDS,
            )
        try:
            conn.request("POST", path, body=body, headers=headers)
            resp = conn.getresponse()
            resp.read(1024)
        finally:
            conn.close()
    except Exception:
        logger.debug("OTLP span export skipped/failed", exc_info=True)


def _record_completed_span(span: SpanRecord) -> None:
    with _BUFFER_LOCK:
        _RECENT_SPANS.append(span)
    endpoint = str(getattr(settings, "OTEL_EXPORTER_OTLP_ENDPOINT", "") or "").strip()
    if endpoint:
        _send_otlp_http(endpoint, build_otlp_payload(span))


@contextmanager
def start_span(
    name: str,
    *,
    kind: str = "INTERNAL",
    parent_traceparent: str | None = None,
    attributes: dict[str, Any] | None = None,
) -> Iterator[SpanRecord]:
    """Start a distributed trace span, bind it to ``contextvars``, and export on exit."""
    inherited = (
        parse_traceparent(parent_traceparent) if parent_traceparent else get_current_trace_context()
    )
    trace_id = inherited.trace_id if inherited is not None else generate_trace_id()
    parent_span_id = inherited.span_id if inherited is not None else None
    span_id = generate_span_id()
    sampled = inherited.sampled if inherited is not None else True

    span = SpanRecord(
        name=name,
        trace_id=trace_id,
        span_id=span_id,
        parent_span_id=parent_span_id,
        kind=kind,
        start_time_unix_nano=time.time_ns(),
        attributes=dict(attributes or {}),
    )
    token = _CURRENT_TRACE.set(TraceContext(trace_id=trace_id, span_id=span_id, sampled=sampled))
    try:
        yield span
    except Exception as exc:
        span.set_error(f"{type(exc).__name__}: {exc}")
        raise
    finally:
        span.end_time_unix_nano = max(span.start_time_unix_nano + 1, time.time_ns())
        _CURRENT_TRACE.reset(token)
        if sampled:
            _record_completed_span(span)
