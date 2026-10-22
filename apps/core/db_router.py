"""Read-replica database router with read-your-own-writes transaction pinning.

Routes analytical, reporting, and dataset export ``SELECT`` queries inside a
``with use_read_replica():`` block to the ``replica`` PostgreSQL alias when
configured, while pinning all writes and in-transaction reads (``in_atomic_block``)
to ``default`` so callers never observe stale uncommitted state.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

from django.conf import settings
from django.db import connections
from django.utils.connection import ConnectionDoesNotExist

PRIMARY_DB_ALIAS = "default"
REPLICA_DB_ALIAS = "replica"

_READ_REPLICA_ENABLED: ContextVar[bool] = ContextVar(
    "mltask_read_replica_enabled",
    default=False,
)
_FORCE_REPLICA: ContextVar[bool] = ContextVar(
    "mltask_force_read_replica",
    default=False,
)


def is_replica_configured() -> bool:
    """Return True when a dedicated ``replica`` database alias is configured and registered."""
    databases = getattr(settings, "DATABASES", {})
    if not (isinstance(databases, dict) and REPLICA_DB_ALIAS in databases):
        return False
    return REPLICA_DB_ALIAS in connections.databases


def resolve_read_db_alias() -> str:
    """Resolve active read alias, falling back to ``default`` inside atomic write blocks."""
    if not _READ_REPLICA_ENABLED.get() or not is_replica_configured():
        return PRIMARY_DB_ALIAS
    try:
        replica_conn = connections[REPLICA_DB_ALIAS]
    except ConnectionDoesNotExist:
        return PRIMARY_DB_ALIAS
    if type(getattr(replica_conn, "cursor", None)).__name__ == "_DatabaseFailure":
        return PRIMARY_DB_ALIAS
    if not _FORCE_REPLICA.get() and connections[PRIMARY_DB_ALIAS].in_atomic_block:
        return PRIMARY_DB_ALIAS
    return REPLICA_DB_ALIAS


@contextmanager
def use_read_replica(*, force: bool = False) -> Iterator[str]:
    """Route ORM ``SELECT`` queries within this block to ``replica`` when safe and configured.

    Yields ``"replica"`` when routed to the read replica or ``"primary"`` when
    pinned to ``default`` (e.g. no replica configured or active atomic write block).
    """
    enabled_token = _READ_REPLICA_ENABLED.set(True)
    force_token = _FORCE_REPLICA.set(force)
    try:
        target = "replica" if resolve_read_db_alias() == REPLICA_DB_ALIAS else "primary"
        yield target
    finally:
        _FORCE_REPLICA.reset(force_token)
        _READ_REPLICA_ENABLED.reset(enabled_token)


class ReplicaDatabaseRouter:
    """Django database router steering opt-in read workloads to ``replica``."""

    _MANAGED_ALIASES = frozenset({PRIMARY_DB_ALIAS, REPLICA_DB_ALIAS, None})

    def db_for_read(self, model: Any, **hints: Any) -> str:
        return resolve_read_db_alias()

    def db_for_write(self, model: Any, **hints: Any) -> str:
        return PRIMARY_DB_ALIAS

    def allow_relation(self, obj1: Any, obj2: Any, **hints: Any) -> bool | None:
        db1 = getattr(getattr(obj1, "_state", None), "db", None)
        db2 = getattr(getattr(obj2, "_state", None), "db", None)
        if db1 in self._MANAGED_ALIASES and db2 in self._MANAGED_ALIASES:
            return True
        return None

    def allow_migrate(
        self,
        db: str,
        app_label: str,
        model_name: str | None = None,
        **hints: Any,
    ) -> bool:
        return db == PRIMARY_DB_ALIAS
