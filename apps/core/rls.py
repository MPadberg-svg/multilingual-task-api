"""PostgreSQL 16 Row-Level Security (RLS) session context and middleware.

Synchronizes tenant and principal identifiers into PostgreSQL custom GUC session
variables (``app.rls_enforced``, ``app.current_organization_id``,
``app.current_user_id``, ``app.rls_bypass``) lazily before SQL execution and
resets them deterministically when requests or context blocks exit so pooled
connections (``CONN_MAX_AGE``) never leak tenant state across requests.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

from django.db import connections
from django.http import HttpRequest, HttpResponse

_TRANSACTION_STATUS_INERROR = 3

_SET_CONFIG_SQL = (
    "SELECT "
    "set_config('app.rls_enforced', %s, false), "
    "set_config('app.current_organization_id', %s, false), "
    "set_config('app.current_user_id', %s, false), "
    "set_config('app.rls_bypass', %s, false)"
)

_EMPTY_GUC_TUPLE: tuple[str, str, str, str] = ("", "", "", "")


@dataclass(frozen=True)
class RLSScope:
    """Immutable PostgreSQL Row-Level Security scope descriptor."""

    enforced: bool = False
    organization_id: str = ""
    user_id: str = ""
    bypass: bool = False

    def as_guc_tuple(self) -> tuple[str, str, str, str]:
        """Serialize scope into the 4-tuple consumed by PostgreSQL ``set_config``."""
        return (
            "on" if self.enforced else "",
            self.organization_id,
            self.user_id,
            "on" if self.bypass else "",
        )


_EXPLICIT_RLS_SCOPE: ContextVar[RLSScope | None] = ContextVar(
    "mltask_explicit_rls_scope",
    default=None,
)
_ACTIVE_HTTP_REQUEST: ContextVar[HttpRequest | None] = ContextVar(
    "mltask_rls_http_request",
    default=None,
)


def get_effective_rls_scope() -> RLSScope:
    """Compute the active ``RLSScope`` from explicit context overrides or HTTP request state."""
    explicit = _EXPLICIT_RLS_SCOPE.get()
    if explicit is not None:
        return explicit

    request = _ACTIVE_HTTP_REQUEST.get()
    if request is not None:
        org = getattr(request, "organization", None)
        org_id = str(org.id) if org is not None and getattr(org, "id", None) else ""
        user = getattr(request, "user", None)
        user_id = ""
        is_admin_console = False
        if user is not None and getattr(user, "is_authenticated", False):
            raw_uid = getattr(user, "id", None)
            user_id = str(raw_uid) if raw_uid is not None else ""
            is_admin_console = bool(
                request.path.startswith("/admin/") and getattr(user, "is_superuser", False)
            )
        return RLSScope(
            enforced=not is_admin_console,
            organization_id=org_id,
            user_id=user_id,
            bypass=is_admin_console,
        )

    return RLSScope()


def _sync_postgres_gucs(conn: Any, target: tuple[str, str, str, str]) -> None:
    """Apply ``target`` GUC tuple on an open PostgreSQL connection when state differs."""
    if getattr(conn, "vendor", "") != "postgresql":
        return

    raw_conn = getattr(conn, "connection", None)
    if raw_conn is None or getattr(raw_conn, "closed", 1) != 0:
        setattr(conn, "_mltask_rls_state", None)
        return

    info = getattr(raw_conn, "info", None)
    if getattr(info, "transaction_status", 0) == _TRANSACTION_STATUS_INERROR:
        # Aborted PostgreSQL transaction blocks ignore SQL until ROLLBACK/SAVEPOINT release;
        # invalidate cached state so the next healthy query re-applies its exact scope.
        setattr(conn, "_mltask_rls_state", None)
        return

    expected_marker = (id(raw_conn), target)
    if getattr(conn, "_mltask_rls_state", None) == expected_marker:
        return

    with raw_conn.cursor() as raw_cursor:
        raw_cursor.execute(_SET_CONFIG_SQL, target)
    setattr(conn, "_mltask_rls_state", expected_marker)


def _reset_if_dirty(conn: Any) -> None:
    """Reset PostgreSQL RLS GUC state to empty defaults if ``conn`` was modified."""
    if getattr(conn, "vendor", "") != "postgresql":
        return
    state = getattr(conn, "_mltask_rls_state", None)
    if state is None or state[1] == _EMPTY_GUC_TUPLE:
        return
    try:
        _sync_postgres_gucs(conn, _EMPTY_GUC_TUPLE)
    except Exception:
        setattr(conn, "_mltask_rls_state", None)


def _rls_execute_wrapper(
    execute: Callable[..., Any],
    sql: str,
    params: Any,
    many: bool,
    context: dict[str, Any],
) -> Any:
    """Django database execute_wrapper that binds active RLS GUCs prior to query execution."""
    conn = context.get("connection")
    if conn is not None and getattr(conn, "vendor", "") == "postgresql":
        _sync_postgres_gucs(conn, get_effective_rls_scope().as_guc_tuple())
    return execute(sql, params, many, context)


@contextmanager
def _install_wrapper_once(conn: Any) -> Iterator[None]:
    """Install ``_rls_execute_wrapper`` at most once per nested call stack on ``conn``."""
    depth = int(getattr(conn, "_mltask_rls_wrapper_depth", 0))
    setattr(conn, "_mltask_rls_wrapper_depth", depth + 1)
    try:
        if depth == 0:
            with conn.execute_wrapper(_rls_execute_wrapper):
                yield
        else:
            yield
    finally:
        new_depth = depth
        setattr(conn, "_mltask_rls_wrapper_depth", new_depth)
        if new_depth == 0:
            _reset_if_dirty(conn)
        else:
            _sync_postgres_gucs(conn, get_effective_rls_scope().as_guc_tuple())


@contextmanager
def rls_context(
    *,
    organization_id: str | None = None,
    user_id: str | None = None,
    enforced: bool = True,
    using: str = "default",
) -> Iterator[RLSScope]:
    """Bind an explicit PostgreSQL RLS tenant/user context for the duration of a ``with`` block."""
    scope = RLSScope(
        enforced=enforced,
        organization_id=str(organization_id) if organization_id else "",
        user_id=str(user_id) if user_id else "",
        bypass=False,
    )
    conn = connections[using]
    with _install_wrapper_once(conn):
        token = _EXPLICIT_RLS_SCOPE.set(scope)
        try:
            _sync_postgres_gucs(conn, scope.as_guc_tuple())
            yield scope
        finally:
            _EXPLICIT_RLS_SCOPE.reset(token)


@contextmanager
def rls_bypass(*, using: str = "default") -> Iterator[RLSScope]:
    """Explicitly bypass PostgreSQL RLS policies for trusted system/relay operations."""
    scope = RLSScope(enforced=False, organization_id="", user_id="", bypass=True)
    conn = connections[using]
    with _install_wrapper_once(conn):
        token = _EXPLICIT_RLS_SCOPE.set(scope)
        try:
            _sync_postgres_gucs(conn, scope.as_guc_tuple())
            yield scope
        finally:
            _EXPLICIT_RLS_SCOPE.reset(token)


class PostgresRLSMiddleware:
    """Bind request tenant/user context into PostgreSQL RLS session GUCs for every HTTP request."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        req_token = _ACTIVE_HTTP_REQUEST.set(request)
        try:
            with ExitStack() as stack:
                stack.enter_context(_install_wrapper_once(connections["default"]))
                return self.get_response(request)
        finally:
            _ACTIVE_HTTP_REQUEST.reset(req_token)
