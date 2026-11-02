"""Make tenant table policies fail closed for non-owner runtime DB roles.

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8

This migration does NOT FORCE RLS for the owner: maintenance operations still
need a separate privileged connection until the API/worker DB role split is
complete. Production runtime DB credentials must not own tables and must not
have BYPASSRLS. That split remains a mandatory deployment gate.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = 'd4e5f6a7b8c9'
down_revision = 'c3d4e5f6a7b8'
branch_labels = None
depends_on = None

# These identity tables participate in unauthenticated authentication/bootstrap
# and must be separated behind a dedicated auth role before enabling RLS on them.
BOOTSTRAP_TABLES = frozenset({'api_keys', 'memberships', 'oidc_identities'})

# Historical tables covered by the previous a1b2c3d4e5f6 migration, retained
# for a reversible downgrade.
LEGACY_TABLES = (
    'assets', 'asset_authorizations', 'asset_credentials', 'findings', 'events',
    'runs', 'investigations', 'approvals', 'detections', 'detection_rules',
    'detection_runs', 'collector_configs', 'collector_runs', 'integration_configs',
    'webhook_deliveries', 'test_scopes', 'test_runs', 'test_results', 'pentest_runs',
    'pentest_hypotheses', 'discovery_runs', 'discoveries', 'request_captures',
    'oob_tokens', 'poc_requests', 'poc_approvals', 'poc_runs', 'action_requests',
    'action_approvals', 'action_runs', 'response_playbooks',
    'autoresponse_executions', 'agent_runs', 'ai_services', 'ai_gateway_requests',
    'canaries', 'canary_hits', 'simulation_runs', 'audit_entries',
)


def _tenant_tables(bind):
    inspector = sa.inspect(bind)
    return sorted(
        table for table in inspector.get_table_names()
        if table not in BOOTSTRAP_TABLES
        and 'tenant_id' in {col['name'] for col in inspector.get_columns(table)}
    )


def _quoted(table):
    # Table names originate from the PostgreSQL catalog; quote them as identifiers.
    return '"' + table.replace('"', '""') + '"'


def upgrade():
    bind = op.get_bind()
    if bind.dialect.name != 'postgresql':
        return
    for table in _tenant_tables(bind):
        ident = _quoted(table)
        op.execute(sa.text(f'ALTER TABLE {ident} ENABLE ROW LEVEL SECURITY'))
        op.execute(sa.text(f'DROP POLICY IF EXISTS tenant_isolation_policy ON {ident}'))
        op.execute(sa.text(
            f'CREATE POLICY tenant_isolation_policy ON {ident} '
            "USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')) "
            "WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))"
        ))


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name != 'postgresql':
        return
    for table in _tenant_tables(bind):
        ident = _quoted(table)
        op.execute(sa.text(f'DROP POLICY IF EXISTS tenant_isolation_policy ON {ident}'))
        if table in LEGACY_TABLES:
            op.execute(sa.text(
                f'CREATE POLICY tenant_isolation_policy ON {ident} '
                "USING (current_setting('app.tenant_id', true) IS NULL "
                "OR current_setting('app.tenant_id', true) = '' "
                "OR tenant_id = current_setting('app.tenant_id', true))"
            ))
        else:
            op.execute(sa.text(f'ALTER TABLE {ident} DISABLE ROW LEVEL SECURITY'))
