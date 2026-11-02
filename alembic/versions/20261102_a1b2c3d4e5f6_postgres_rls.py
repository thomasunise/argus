"""PostgreSQL Row-Level Security (RLS) defense-in-depth for tenant-scoped tables\n\nNo tenant context means no tenant rows. Production MUST connect through a dedicated\nnon-owner, non-BYPASSRLS runtime role; migration ownership must stay separate.

Revision ID: a1b2c3d4e5f6
Revises: a4c8e2f1b356
Create Date: 2026-11-02 07:15:00.000000+00:00
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, None] = 'a4c8e2f1b356'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

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
    inspector = sa.inspect(bind)
    existing = set(inspector.get_table_names())
    for table in TENANT_TABLES:
        if table not in existing:
            continue
        op.execute(sa.text(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY'))
        op.execute(sa.text(f'DROP POLICY IF EXISTS tenant_isolation_policy ON "{table}"'))
        op.execute(
            sa.text(
                f'CREATE POLICY tenant_isolation_policy ON "{table}" '
                "USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')) "
                "WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))"
            )
        )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != 'postgresql':
        return
    inspector = sa.inspect(bind)
    existing = set(inspector.get_table_names())
    for table in TENANT_TABLES:
        if table not in existing:
            continue
        op.execute(sa.text(f'DROP POLICY IF EXISTS tenant_isolation_policy ON "{table}"'))
        op.execute(sa.text(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY'))
