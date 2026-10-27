"""Discovery loop: runs and facts

Revision ID: b7d2e4f19c33
Revises: 9c41a7d2e6b8
Create Date: 2026-10-26 14:05:00.000000+00:00
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = 'b7d2e4f19c33'
down_revision: Union[str, None] = '9c41a7d2e6b8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'discovery_runs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=36), nullable=False),
        sa.Column('asset_id', sa.String(length=36), nullable=False),
        sa.Column('scope_id', sa.String(length=36), nullable=False),
        sa.Column('status', sa.String(length=12), nullable=False),
        sa.Column('discovery_count', sa.Integer(), nullable=False),
        sa.Column('follow_up_count', sa.Integer(), nullable=False),
        sa.Column('error', sa.Text(), nullable=False),
        sa.Column('job_id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id']),
        sa.ForeignKeyConstraint(['scope_id'], ['test_scopes.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('discovery_runs', schema=None) as batch_op:
        batch_op.create_index('ix_discovery_runs_tenant_id', ['tenant_id'], unique=False)
        batch_op.create_index('ix_discovery_runs_tenant_created', ['tenant_id', 'created_at'], unique=False)
        batch_op.create_index('ix_discovery_runs_asset_id', ['asset_id'], unique=False)
        batch_op.create_index('ix_discovery_runs_scope_id', ['scope_id'], unique=False)

    op.create_table(
        'discoveries',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=36), nullable=False),
        sa.Column('asset_id', sa.String(length=36), nullable=False),
        sa.Column('run_id', sa.String(length=36), nullable=False),
        sa.Column('kind', sa.String(length=16), nullable=False),
        sa.Column('value', sa.String(length=512), nullable=False),
        sa.Column('source', sa.String(length=64), nullable=False),
        sa.Column('confidence', sa.String(length=8), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('test_run_id', sa.String(length=36), nullable=False),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id']),
        sa.ForeignKeyConstraint(['run_id'], ['discovery_runs.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('tenant_id', 'asset_id', 'kind', 'value', name='uq_discovery_fact'),
    )
    with op.batch_alter_table('discoveries', schema=None) as batch_op:
        batch_op.create_index('ix_discoveries_tenant_id', ['tenant_id'], unique=False)
        batch_op.create_index('ix_discoveries_tenant_status', ['tenant_id', 'status'], unique=False)
        batch_op.create_index('ix_discoveries_asset_id', ['asset_id'], unique=False)
        batch_op.create_index('ix_discoveries_run_id', ['run_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('discoveries', schema=None) as batch_op:
        batch_op.drop_index('ix_discoveries_run_id')
        batch_op.drop_index('ix_discoveries_asset_id')
        batch_op.drop_index('ix_discoveries_tenant_status')
        batch_op.drop_index('ix_discoveries_tenant_id')
    op.drop_table('discoveries')

    with op.batch_alter_table('discovery_runs', schema=None) as batch_op:
        batch_op.drop_index('ix_discovery_runs_scope_id')
        batch_op.drop_index('ix_discovery_runs_asset_id')
        batch_op.drop_index('ix_discovery_runs_tenant_created')
        batch_op.drop_index('ix_discovery_runs_tenant_id')
    op.drop_table('discovery_runs')
