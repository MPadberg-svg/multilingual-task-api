"""Attach PostgreSQL 16 Row-Level Security policy to v1.8.0 AnnotatorCalibration table."""

from __future__ import annotations

from typing import Any

from django.db import migrations


def _calibration_policy_sql() -> str:
    table_name = "tasks_annotatorcalibration"
    predicate = f"""(
        COALESCE(current_setting('app.rls_bypass', true), '') = 'on'
        OR COALESCE(current_setting('app.rls_enforced', true), '') <> 'on'
        OR (
            CASE
                WHEN NULLIF(current_setting('app.current_organization_id', true), '') IS NOT NULL THEN
                    organization_id::text = current_setting('app.current_organization_id', true)
                WHEN NULLIF(current_setting('app.current_user_id', true), '') IS NOT NULL THEN
                    EXISTS (
                        SELECT 1 FROM core_organizationmember om
                        WHERE om.organization_id = {table_name}.organization_id
                          AND om.user_id::text = current_setting('app.current_user_id', true)
                    )
                ELSE FALSE
            END
        )
    )"""
    policy_name = f"{table_name}_tenant_isolation"
    return f"""
    ALTER TABLE {table_name} ENABLE ROW LEVEL SECURITY;
    ALTER TABLE {table_name} FORCE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS {policy_name} ON {table_name};
    CREATE POLICY {policy_name} ON {table_name}
        AS PERMISSIVE
        FOR ALL
        USING {predicate}
        WITH CHECK {predicate};
    """


def apply_v180_rls(apps: Any, schema_editor: Any) -> None:
    """Grant runtime privileges and attach tenant RLS policy to tasks_annotatorcalibration."""
    if schema_editor.connection.vendor != "postgresql":
        return

    with schema_editor.connection.cursor() as cursor:
        cursor.execute("""
            DO $$
            BEGIN
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mltask_rls_app') THEN
                    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE
                        tasks_annotatorcalibration
                    TO mltask_rls_app;
                END IF;
            END
            $$;
            """)
        cursor.execute(_calibration_policy_sql())


def remove_v180_rls(apps: Any, schema_editor: Any) -> None:
    """Drop v1.8.0 RLS policy cleanly on reverse migration."""
    if schema_editor.connection.vendor != "postgresql":
        return

    with schema_editor.connection.cursor() as cursor:
        table_name = "tasks_annotatorcalibration"
        policy_name = f"{table_name}_tenant_isolation"
        cursor.execute(f"DROP POLICY IF EXISTS {policy_name} ON {table_name};")
        cursor.execute(f"ALTER TABLE {table_name} NO FORCE ROW LEVEL SECURITY;")
        cursor.execute(f"ALTER TABLE {table_name} DISABLE ROW LEVEL SECURITY;")


class Migration(migrations.Migration):
    dependencies = [
        ("tasks", "0008_v180_audit_chain_and_gold_calibration"),
    ]

    operations = [
        migrations.RunPython(apply_v180_rls, remove_v180_rls),
    ]
