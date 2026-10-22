"""SSRF-hardened, HMAC-SHA256-signed outbound webhook validation and delivery."""

from __future__ import annotations

import hashlib
import hmac
import http.client
import ipaddress
import json
import logging
import socket
import ssl
import time
import urllib.parse
import uuid
from typing import Any

from django.conf import settings
from django.utils import timezone

from apps.core.models import WebhookDelivery, WebhookEndpoint
from apps.core.tracing import start_span

logger = logging.getLogger(__name__)

WEBHOOK_TIMEOUT_SECONDS: float = 5.0
MAX_CONSECUTIVE_WEBHOOK_FAILURES: int = 10


def _is_forbidden_ip(ip_str: str) -> bool:
    """Return True if ``ip_str`` is loopback, private, link-local, multicast, or reserved."""
    addr = ipaddress.ip_address(ip_str)
    return bool(
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def validate_webhook_url(url: str, *, resolve_dns: bool = False) -> str:
    """Validate webhook target URL against SSRF (scheme, host, private/metadata IPs).

    Args:
        url: Candidate target URL.
        resolve_dns: When True (used immediately before outbound HTTP dispatch),
            resolves hostname via DNS and verifies every returned A/AAAA record
            is a globally routable public IP.

    Raises:
        ValueError: If the URL is malformed, uses a disallowed scheme, or targets
            an internal/private/loopback/link-local host.
    """
    cleaned = (url or "").strip()
    parsed = urllib.parse.urlparse(cleaned)

    allowed_schemes = {"https", "http"} if settings.DEBUG else {"https"}
    if parsed.scheme.lower() not in allowed_schemes:
        scheme_msg = "https" if not settings.DEBUG else "http or https"
        raise ValueError(f"Webhook URL must use {scheme_msg} scheme.")

    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        raise ValueError("Webhook URL must include a valid hostname.")

    if hostname in {"localhost", "localhost.localdomain"} or hostname.endswith(
        (".local", ".internal", ".localhost")
    ):
        raise ValueError("Webhook URL cannot target internal or localhost hostnames.")

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        is_literal_ip = False
    else:
        is_literal_ip = True

    if is_literal_ip and _is_forbidden_ip(hostname):
        raise ValueError("Webhook URL cannot target private, loopback, or metadata IP ranges.")

    if resolve_dns and not is_literal_ip:
        default_port = 443 if parsed.scheme.lower() == "https" else 80
        try:
            addr_infos = socket.getaddrinfo(hostname, parsed.port or default_port)
        except socket.gaierror as exc:
            raise ValueError(f"Unable to resolve webhook hostname '{hostname}'.") from exc

        if not addr_infos:
            raise ValueError(f"No DNS records found for webhook hostname '{hostname}'.")

        for info in addr_infos:
            resolved_ip = str(info[4][0])
            if _is_forbidden_ip(resolved_ip):
                raise ValueError(
                    "Webhook hostname resolved to a forbidden private or metadata IP address."
                )

    return cleaned


def sign_webhook_payload(secret: str, timestamp: int, body_bytes: bytes) -> str:
    """Generate ``sha256=<hex>`` HMAC signature over ``<timestamp>.<body>``."""
    signing_input = f"{timestamp}.".encode("utf-8") + body_bytes
    digest = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def _send_http_post_no_redirect(
    safe_url: str,
    body_bytes: bytes,
    headers: dict[str, str],
) -> int:
    """Dispatch a single non-redirecting HTTP(S) POST with verified TLS and strict timeout."""
    parsed = urllib.parse.urlparse(safe_url)
    scheme = parsed.scheme.lower()
    host = parsed.hostname or ""
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    conn: http.client.HTTPConnection
    if scheme == "https":
        port = parsed.port or 443
        tls_ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(
            host, port=port, timeout=WEBHOOK_TIMEOUT_SECONDS, context=tls_ctx
        )
    else:
        port = parsed.port or 80
        conn = http.client.HTTPConnection(host, port=port, timeout=WEBHOOK_TIMEOUT_SECONDS)

    try:
        conn.request("POST", path, body=body_bytes, headers=headers)
        resp = conn.getresponse()
        resp.read(4096)
        return int(resp.status)
    finally:
        conn.close()


def deliver_webhook_sync(
    endpoint: WebhookEndpoint,
    event_type: str,
    event_payload: dict[str, Any],
) -> WebhookDelivery:
    """Deliver a single signed webhook HTTP POST synchronously with SSRF & redirect protection."""
    delivery_id = uuid.uuid4()
    timestamp = int(time.time())
    envelope = {
        "id": str(delivery_id),
        "event": event_type,
        "organization_id": str(endpoint.organization_id),
        "timestamp": timestamp,
        "data": event_payload,
    }
    body_bytes = json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature = sign_webhook_payload(endpoint.secret, timestamp, body_bytes)

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "MultilingualTaskAPI-Webhook/1.2",
        "X-MLTask-Delivery": str(delivery_id),
        "X-MLTask-Event": event_type,
        "X-MLTask-Timestamp": str(timestamp),
        "X-MLTask-Signature-256": signature,
    }

    status_code: int | None = None
    success = False
    error_message = ""

    with start_span(
        "webhook.deliver",
        kind="CLIENT",
        attributes={
            "webhook.id": str(endpoint.id),
            "webhook.event": event_type,
            "organization.id": str(endpoint.organization_id),
        },
    ) as span:
        headers["traceparent"] = span.traceparent
        try:
            safe_url = validate_webhook_url(endpoint.url, resolve_dns=True)
            status_code = _send_http_post_no_redirect(safe_url, body_bytes, headers)
            span.set_attribute("http.status_code", status_code)
            success = 200 <= status_code < 300
            if not success:
                error_message = f"Non-2xx HTTP status {status_code}"
                span.set_error(error_message)
        except Exception as exc:
            error_message = str(exc)[:450]
            span.set_error(error_message)

    now = timezone.now()
    if success:
        endpoint.failure_count = 0
        endpoint.last_triggered_at = now
        endpoint.save(update_fields=["failure_count", "last_triggered_at"])
    else:
        endpoint.failure_count += 1
        endpoint.last_triggered_at = now
        if endpoint.failure_count >= MAX_CONSECUTIVE_WEBHOOK_FAILURES:
            endpoint.is_active = False
        endpoint.save(update_fields=["failure_count", "last_triggered_at", "is_active"])

    return WebhookDelivery.objects.create(
        id=delivery_id,
        endpoint=endpoint,
        event_type=event_type,
        payload=envelope,
        response_status=status_code,
        success=success,
        error_message=error_message,
    )


def dispatch_organization_webhooks(
    organization_id: str | None,
    event_type: str,
    payload: dict[str, Any],
    *,
    raise_on_broker_error: bool = False,
) -> int:
    """Enqueue Celery webhook deliveries for all matching active organization endpoints."""
    if not organization_id or organization_id == "global":
        return 0

    endpoints = list(
        WebhookEndpoint.objects.filter(
            organization_id=organization_id,
            is_active=True,
        ).only("id", "events")
    )
    matching_ids = [
        str(ep.id)
        for ep in endpoints
        if event_type in (ep.events or []) or "*" in (ep.events or [])
    ]
    if not matching_ids:
        return 0

    from apps.tasks.tasks import deliver_webhook_event

    dispatched = 0
    for ep_id in matching_ids:
        try:
            deliver_webhook_event.delay(ep_id, event_type, payload)
            dispatched += 1
        except Exception:
            if raise_on_broker_error:
                raise
            logger.warning("Unable to enqueue webhook delivery for endpoint %s", ep_id)
    return dispatched
