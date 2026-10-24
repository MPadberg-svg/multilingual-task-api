"""Attach PostgreSQL 16 Row-Level Security policy to v1.9.0 AuditChainCheckpoint table."""

from __future__ import annotations

from typing import Any

from django.db import migrations

CHECKPOINT_RLS_SQL = """
ALTER TABLE core_auditchaincheckpoint ENABLE ROW LEVEL SECURITY;
ALTER TABLE core_auditchaincheckpoint FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS core_auditchaincheckpoint_tenant_isolation ON core_auditchaincheckpoint;
CREATE POLICY core_auditchaincheckpoint_tenant_isolation ON core_auditchaincheckpoint
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
                        WHERE om.organization_id = core_auditchaincheckpoint.organization_id
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
                        WHERE om.organization_id = core_auditchaincheckpoint.organization_id
                          AND om.user_id::text = current_setting('app.current_user_id', true)
                    )
                ELSE FALSE
            END
        )
    );
"""


def apply_v190_rls(apps: Any, schema_editor: Any) -> None:
    """Grant runtime privileges and attach tenant RLS policy to core_auditchaincheckpoint."""
    if schema_editor.connection.vendor != "postgresql":
        return

    with schema_editor.connection.cursor() as cursor:
        cursor.execute("""
            DO $$
            BEGIN
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mltask_rls_app') THEN
                    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE
                        core_auditchaincheckpoint
                    TO mltask_rls_app;
                END IF;
            END
            $$;
            """)
        cursor.execute(CHECKPOINT_RLS_SQL)


def remove_v190_rls(apps: Any, schema_editor: Any) -> None:
    """Drop v1.9.0 RLS policy cleanly on reverse migration."""
    if schema_editor.connection.vendor != "postgresql":
        return

    with schema_editor.connection.cursor() as cursor:
        cursor.execute(
            "DROP POLICY IF EXISTS core_auditchaincheckpoint_tenant_isolation "
            "ON core_auditchaincheckpoint;"
        )
        cursor.execute("ALTER TABLE core_auditchaincheckpoint NO FORCE ROW LEVEL SECURITY;")
        cursor.execute("ALTER TABLE core_auditchaincheckpoint DISABLE ROW LEVEL SECURITY;")


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0007_v190_worm_checkpoints_and_domain_skill_vectors"),
        ("tasks", "0010_v190_worm_checkpoints_and_domain_skill_vectors"),
    ]

    operations = [
        migrations.RunPython(apply_v190_rls, remove_v190_rls),
    ]
