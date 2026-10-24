"""Attach PostgreSQL 16 Row-Level Security policy to v1.11.0 DomainUncertaintyPolicy table."""

from __future__ import annotations

from typing import Any

from django.db import migrations

DOMAIN_UNCERTAINTY_POLICY_RLS_SQL = """
ALTER TABLE tasks_domainuncertaintypolicy ENABLE ROW LEVEL SECURITY;
ALTER TABLE tasks_domainuncertaintypolicy FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tasks_domainuncertaintypolicy_tenant_isolation
    ON tasks_domainuncertaintypolicy;
CREATE POLICY tasks_domainuncertaintypolicy_tenant_isolation
    ON tasks_domainuncertaintypolicy
    AS PERMISSIVE
    FOR ALL
    USING (
        COALESCE(current_setting('app.rls_bypass', true), '') = 'on'
        OR COALESCE(current_setting('app.rls_enforced', true), '') <> 'on'
        OR (
            CASE
                WHEN NULLIF(current_setting('app.current_organization_id', true), '') IS NOT NULL THEN
                    organization_id::text = current_setting('app.current_organization_id', true)
                WHEN NULLIF(current_setting('app.current_user_id', true), '') IS NOT NULL THEN
                    EXISTS (
                        SELECT 1 FROM core_organizationmember om
                        WHERE om.organization_id = tasks_domainuncertaintypolicy.organization_id
                          AND om.user_id::text = current_setting('app.current_user_id', true)
                    )
                ELSE FALSE
            END
        )
    )
    WITH CHECK (
        COALESCE(current_setting('app.rls_bypass', true), '') = 'on'
        OR COALESCE(current_setting('app.rls_enforced', true), '') <> 'on'
        OR (
            CASE
                WHEN NULLIF(current_setting('app.current_organization_id', true), '') IS NOT NULL THEN
                    organization_id::text = current_setting('app.current_organization_id', true)
                WHEN NULLIF(current_setting('app.current_user_id', true), '') IS NOT NULL THEN
                    EXISTS (
                        SELECT 1 FROM core_organizationmember om
                        WHERE om.organization_id = tasks_domainuncertaintypolicy.organization_id
                          AND om.user_id::text = current_setting('app.current_user_id', true)
                    )
                ELSE FALSE
            END
        )
    );
"""


def apply_v1110_rls(apps: Any, schema_editor: Any) -> None:
    """Grant runtime privileges and attach tenant RLS policy to tasks_domainuncertaintypolicy."""
    if schema_editor.connection.vendor != "postgresql":
        return

    with schema_editor.connection.cursor() as cursor:
        cursor.execute("""
            DO $$
            BEGIN
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mltask_rls_app') THEN
                    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE
                        tasks_domainuncertaintypolicy
                    TO mltask_rls_app;
                END IF;
            END
            $$;
            """)
        cursor.execute(DOMAIN_UNCERTAINTY_POLICY_RLS_SQL)


def remove_v1110_rls(apps: Any, schema_editor: Any) -> None:
    """Drop v1.11.0 RLS policy cleanly on reverse migration."""
    if schema_editor.connection.vendor != "postgresql":
        return

    with schema_editor.connection.cursor() as cursor:
        cursor.execute(
            "DROP POLICY IF EXISTS tasks_domainuncertaintypolicy_tenant_isolation "
            "ON tasks_domainuncertaintypolicy;"
        )
        cursor.execute("ALTER TABLE tasks_domainuncertaintypolicy NO FORCE ROW LEVEL SECURITY;")
        cursor.execute("ALTER TABLE tasks_domainuncertaintypolicy DISABLE ROW LEVEL SECURITY;")


class Migration(migrations.Migration):
    dependencies = [
        ("tasks", "0013_v1110_merkle_proofs_dpo_export_and_adaptive_thresholds"),
    ]

    operations = [
        migrations.RunPython(apply_v1110_rls, remove_v1110_rls),
    ]
