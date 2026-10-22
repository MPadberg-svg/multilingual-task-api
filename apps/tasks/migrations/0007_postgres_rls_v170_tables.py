"""Attach PostgreSQL 16 Row-Level Security policies to v1.7.0 SSO and AI FinOps tables."""

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


def apply_v170_rls(apps: Any, schema_editor: Any) -> None:
    """Grant runtime privileges and attach tenant RLS policies to v1.7.0 tables."""
    if schema_editor.connection.vendor != "postgresql":
        return

    with schema_editor.connection.cursor() as cursor:
        cursor.execute("""
            DO $$
            BEGIN
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mltask_rls_app') THEN
                    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE
                        core_organizationssoconfig,
                        core_aiusagelog
                    TO mltask_rls_app;
                END IF;
            END
            $$;
            """)
        cursor.execute(_org_policy_sql("core_organizationssoconfig"))
        cursor.execute(_org_policy_sql("core_aiusagelog", allow_null_org_for_auth_user=True))


def remove_v170_rls(apps: Any, schema_editor: Any) -> None:
    """Drop v1.7.0 RLS policies cleanly on reverse migration."""
    if schema_editor.connection.vendor != "postgresql":
        return

    with schema_editor.connection.cursor() as cursor:
        for table_name in ("core_organizationssoconfig", "core_aiusagelog"):
            policy_name = f"{table_name}_tenant_isolation"
            cursor.execute(f"DROP POLICY IF EXISTS {policy_name} ON {table_name};")
            cursor.execute(f"ALTER TABLE {table_name} NO FORCE ROW LEVEL SECURITY;")
            cursor.execute(f"ALTER TABLE {table_name} DISABLE ROW LEVEL SECURITY;")


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0005_v170_sso_scim_and_ai_finops"),
        ("tasks", "0006_postgres_pg_trgm_search_indexes"),
    ]

    operations = [
        migrations.RunPython(apply_v170_rls, remove_v170_rls),
    ]
