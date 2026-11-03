"""Re-apply fail-closed RLS policies to existing PostgreSQL databases.

Revision ID: b6a4f37c9120
Revises: a1b2c3d4e5f6

IMPORTANT: application connection must be a non-owner, non-BYPASSRLS role.
The migration role retains ownership and privileges to manage the schema.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = 'b6a4f37c9120'
down_revision = 'a1b2c3d4e5f6'
branch_labels = None
depends_on = None

TENANT_TABLES: tuple[str, ...] = (
    'assets',
    'asset_authorizations',
    'asset_credentials',
    'findings',
    'events',
    'runs',
    'investigations',
    'approvals',
    'detections',
    'detection_rules',
    'detection_runs',
    'collector_configs',
    'collector_runs',
    'integration_configs',
    'webhook_deliveries',
    'test_scopes',
    'test_runs',
    'test_results',
    'pentest_runs',
    'pentest_hypotheses',
    'discovery_runs',
    'discoveries',
    'request_captures',
    'oob_tokens',
    'poc_requests',
    'poc_approvals',
    'poc_runs',
    'action_requests',
    'action_approvals',
    'action_runs',
    'response_playbooks',
    'autoresponse_executions',
    'agent_runs',
    'ai_services',
    'ai_gateway_requests',
    'canaries',
    'canary_hits',
    'simulation_runs',
    'audit_entries',
)


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != 'postgresql':
        return
    existing = set(sa.inspect(bind).get_table_names())
    for table in TENANT_TABLES:
        if table not in existing:
            continue
        op.execute(sa.text(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY'))
        op.execute(sa.text(f'DROP POLICY IF EXISTS tenant_isolation_policy ON "{table}"'))
        op.execute(sa.text(
            f'CREATE POLICY tenant_isolation_policy ON "{table}" '
            "USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')) "
            "WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))"
        ))


def downgrade() -> None:
    # A downgrade must never silently restore the former fail-open policy.
    raise RuntimeError('Refusing to downgrade fail-closed tenant isolation')
