"""Install PostgreSQL 16 ``pg_trgm`` extension and GIN trigram search indexes."""

from __future__ import annotations

from typing import Any

from django.db import migrations


def apply_pg_trgm_indexes(apps: Any, schema_editor: Any) -> None:
    """Enable ``pg_trgm`` and create GIN trigram indexes on translation title & description."""
    if schema_editor.connection.vendor != "postgresql":
        return

    with schema_editor.connection.cursor() as cursor:
        cursor.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm;")
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS tasks_trans_title_trgm_idx
                ON tasks_task_translation USING gin (title gin_trgm_ops);
            CREATE INDEX IF NOT EXISTS tasks_trans_desc_trgm_idx
                ON tasks_task_translation USING gin (description gin_trgm_ops);
            """)


def remove_pg_trgm_indexes(apps: Any, schema_editor: Any) -> None:
    """Drop GIN trigram search indexes cleanly on reverse migration."""
    if schema_editor.connection.vendor != "postgresql":
        return

    with schema_editor.connection.cursor() as cursor:
        cursor.execute("DROP INDEX IF EXISTS tasks_trans_desc_trgm_idx;")
        cursor.execute("DROP INDEX IF EXISTS tasks_trans_title_trgm_idx;")


class Migration(migrations.Migration):
    dependencies = [
        ("tasks", "0005_postgres_rls_policies"),
    ]

    operations = [
        migrations.RunPython(apply_pg_trgm_indexes, remove_pg_trgm_indexes),
    ]
