"""Captured requests for discovery replay

Revision ID: c4e9a1b7d552
Revises: b7d2e4f19c33
Create Date: 2026-10-26 21:40:00.000000+00:00
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = 'c4e9a1b7d552'
down_revision: Union[str, None] = 'b7d2e4f19c33'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'request_captures',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=36), nullable=False),
        sa.Column('asset_id', sa.String(length=36), nullable=False),
        sa.Column('run_id', sa.String(length=36), nullable=False),
        sa.Column('scope_id', sa.String(length=36), nullable=False),
        sa.Column('method', sa.String(length=8), nullable=False),
        sa.Column('path', sa.String(length=512), nullable=False),
        sa.Column('status', sa.Integer(), nullable=False),
        sa.Column('content_type', sa.String(length=120), nullable=False),
        sa.Column('has_auth', sa.Boolean(), nullable=False),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id']),
        sa.ForeignKeyConstraint(['run_id'], ['discovery_runs.id']),
        sa.ForeignKeyConstraint(['scope_id'], ['test_scopes.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('tenant_id', 'asset_id', 'method', 'path', name='uq_capture_request'),
    )
    with op.batch_alter_table('request_captures', schema=None) as batch_op:
        batch_op.create_index('ix_request_captures_tenant_id', ['tenant_id'], unique=False)
        batch_op.create_index('ix_request_captures_asset_id', ['asset_id'], unique=False)
        batch_op.create_index('ix_captures_tenant_seen', ['tenant_id', 'last_seen'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('request_captures', schema=None) as batch_op:
        batch_op.drop_index('ix_captures_tenant_seen')
        batch_op.drop_index('ix_request_captures_asset_id')
        batch_op.drop_index('ix_request_captures_tenant_id')
    op.drop_table('request_captures')
