"""Out-of-band probe tokens

Revision ID: e2a4c6b8d013
Revises: d8f1c3a9e204
Create Date: 2026-10-27 08:40:00.000000+00:00
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = 'e2a4c6b8d013'
down_revision: Union[str, None] = 'd8f1c3a9e204'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'oob_tokens',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=36), nullable=False),
        sa.Column('token', sa.String(length=64), nullable=False),
        sa.Column('asset_id', sa.String(length=36), nullable=False),
        sa.Column('run_id', sa.String(length=36), nullable=False),
        sa.Column('kind', sa.String(length=16), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('first_hit_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('hit_count', sa.Integer(), nullable=False),
        sa.Column('source_ip', sa.String(length=64), nullable=False),
        sa.Column('user_agent', sa.String(length=256), nullable=False),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('oob_tokens', schema=None) as batch_op:
        batch_op.create_index('ix_oob_tokens_token', ['token'], unique=True)
        batch_op.create_index('ix_oob_tokens_tenant_created', ['tenant_id', 'created_at'], unique=False)
        batch_op.create_index('ix_oob_tokens_asset_id', ['asset_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('oob_tokens', schema=None) as batch_op:
        batch_op.drop_index('ix_oob_tokens_asset_id')
        batch_op.drop_index('ix_oob_tokens_tenant_created')
        batch_op.drop_index('ix_oob_tokens_token')
    op.drop_table('oob_tokens')
