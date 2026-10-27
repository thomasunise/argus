"""Per-asset testing credentials

Revision ID: d8f1c3a9e204
Revises: c4e9a1b7d552
Create Date: 2026-10-26 22:55:00.000000+00:00
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = 'd8f1c3a9e204'
down_revision: Union[str, None] = 'c4e9a1b7d552'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'asset_credentials',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=36), nullable=False),
        sa.Column('asset_id', sa.String(length=36), nullable=False),
        sa.Column('kind', sa.String(length=8), nullable=False),
        sa.Column('name', sa.String(length=120), nullable=False),
        sa.Column('secret', sa.Text(), nullable=False),
        sa.Column('created_by', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('asset_credentials', schema=None) as batch_op:
        batch_op.create_index('ix_asset_credentials_tenant_id', ['tenant_id'], unique=False)
        batch_op.create_index('ix_asset_credentials_tenant_asset', ['tenant_id', 'asset_id'], unique=False)
        batch_op.create_index('ix_asset_credentials_asset_id', ['asset_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('asset_credentials', schema=None) as batch_op:
        batch_op.drop_index('ix_asset_credentials_asset_id')
        batch_op.drop_index('ix_asset_credentials_tenant_asset')
        batch_op.drop_index('ix_asset_credentials_tenant_id')
    op.drop_table('asset_credentials')
