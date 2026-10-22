"""Install PostgreSQL 16 Row-Level Security (RLS) tenant-isolation policies."""

from __future__ import annotations

from typing import Any

from django.db import migrations


def _org_policy_sql(table_name: str, *, allow_null_org_for_auth_user: bool = False) -> str:
    null_org_clause = "(organization_id IS NULL) OR " if allow_null_org_for_auth_user else ""
    predicate = f"""(
        COALESCE(current_setting('app.rls_bypass', true), '') = 'on'
        OR COALESCE(current_setting('app.rls_enforced', true), '') <> 'on'
        OR (
            CASE
                WHEN NULLIF(current_setting('app.current_organization_id', true), '') IS NOT NULL THEN
                    organization_id::text = current_setting('app.current_organization_id', true)
                WHEN NULLIF(current_setting('app.current_user_id', true), '') IS NOT NULL THEN
                    (
                        {null_org_clause}EXISTS (
                            SELECT 1 FROM core_organizationmember om
                            WHERE om.organization_id = {table_name}.organization_id
                              AND om.user_id::text = current_setting('app.current_user_id', true)
                        )
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


def _tasks_policy_sql() -> str:
    predicate = """(
        COALESCE(current_setting('app.rls_bypass', true), '') = 'on'
        OR COALESCE(current_setting('app.rls_enforced', true), '') <> 'on'
        OR (
            CASE
                WHEN NULLIF(current_setting('app.current_organization_id', true), '') IS NOT NULL THEN
                    organization_id::text = current_setting('app.current_organization_id', true)
                WHEN NULLIF(current_setting('app.current_user_id', true), '') IS NOT NULL THEN
                    (
                        (
                            organization_id IS NULL
                            AND user_id::text = current_setting('app.current_user_id', true)
                        )
                        OR EXISTS (
                            SELECT 1 FROM core_organizationmember om
                            WHERE om.organization_id = tasks_task.organization_id
                              AND om.user_id::text = current_setting('app.current_user_id', true)
                        )
                    )
                ELSE FALSE
            END
        )
    )"""
    return f"""
    ALTER TABLE tasks_task ENABLE ROW LEVEL SECURITY;
    ALTER TABLE tasks_task FORCE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS tasks_task_tenant_isolation ON tasks_task;
    CREATE POLICY tasks_task_tenant_isolation ON tasks_task
        AS PERMISSIVE
        FOR ALL
        USING {predicate}
        WITH CHECK {predicate};
    """


def apply_postgres_rls(apps: Any, schema_editor: Any) -> None:
    """Create NOBYPASSRLS runtime role and attach tenant RLS policies on PostgreSQL."""
    if schema_editor.connection.vendor != "postgresql":
        return

    with schema_editor.connection.cursor() as cursor:
        cursor.execute("""
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mltask_rls_app') THEN
                    CREATE ROLE mltask_rls_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
                END IF;
            END
            $$;
            GRANT USAGE ON SCHEMA public TO mltask_rls_app;
            GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO mltask_rls_app;
            GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO mltask_rls_app;
            ALTER DEFAULT PRIVILEGES IN SCHEMA public
                GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO mltask_rls_app;
            ALTER DEFAULT PRIVILEGES IN SCHEMA public
                GRANT USAGE, SELECT ON SEQUENCES TO mltask_rls_app;
            """)
        cursor.execute(_tasks_policy_sql())
        cursor.execute(_org_policy_sql("core_organizationapikey"))
        cursor.execute(_org_policy_sql("core_webhookendpoint"))
        cursor.execute(_org_policy_sql("core_outboxevent", allow_null_org_for_auth_user=True))


def remove_postgres_rls(apps: Any, schema_editor: Any) -> None:
    """Drop tenant RLS policies cleanly on reverse migration."""
    if schema_editor.connection.vendor != "postgresql":
        return

    with schema_editor.connection.cursor() as cursor:
        for table_name in (
            "tasks_task",
            "core_organizationapikey",
            "core_webhookendpoint",
            "core_outboxevent",
        ):
            policy_name = f"{table_name}_tenant_isolation"
            cursor.execute(f"DROP POLICY IF EXISTS {policy_name} ON {table_name};")
            cursor.execute(f"ALTER TABLE {table_name} NO FORCE ROW LEVEL SECURITY;")
            cursor.execute(f"ALTER TABLE {table_name} DISABLE ROW LEVEL SECURITY;")


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0004_outboxevent"),
        ("tasks", "0004_taskannotation_task_claimed_by_task_claimed_until_and_more"),
    ]

    operations = [
        migrations.RunPython(apply_postgres_rls, remove_postgres_rls),
    ]
