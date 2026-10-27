"""Add role column to asset_credentials for multi-principal / IDOR testing

Revision ID: a4c8e2f1b356
Revises: f3b5d7c9e124
Create Date: 2026-10-27 11:20:00.000000+00:00
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'a4c8e2f1b356'
down_revision: Union[str, None] = 'f3b5d7c9e124'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('asset_credentials', schema=None) as batch_op:
        batch_op.add_column(sa.Column('role', sa.String(length=40), nullable=False, server_default='default'))


def downgrade() -> None:
    with op.batch_alter_table('asset_credentials', schema=None) as batch_op:
        batch_op.drop_column('role')
