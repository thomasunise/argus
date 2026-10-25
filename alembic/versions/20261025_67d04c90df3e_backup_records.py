"""Backup history (backup_records)

Revision ID: 67d04c90df3e
Revises: 36d73d5a62f5
Create Date: 2026-10-25 06:57:44.789405+00:00
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = '67d04c90df3e'
down_revision: Union[str, None] = '36d73d5a62f5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('backup_records',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('status', sa.String(length=12), nullable=False),
    sa.Column('trigger', sa.String(length=16), nullable=False),
    sa.Column('size_bytes', sa.BigInteger(), nullable=False),
    sa.Column('sha256', sa.String(length=64), nullable=False),
    sa.Column('tables', sa.Integer(), nullable=False),
    sa.Column('rows', sa.BigInteger(), nullable=False),
    sa.Column('encrypted', sa.Boolean(), nullable=False),
    sa.Column('key_id', sa.String(length=40), nullable=False),
    sa.Column('revision', sa.String(length=40), nullable=False),
    sa.Column('stores_json', sa.Text(), nullable=False),
    sa.Column('pruned_json', sa.Text(), nullable=False),
    sa.Column('error', sa.Text(), nullable=False),
    sa.Column('requested_by', sa.String(length=200), nullable=False),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('backup_records', schema=None) as batch_op:
        batch_op.create_index('ix_backup_records_started', ['started_at'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('backup_records', schema=None) as batch_op:
        batch_op.drop_index('ix_backup_records_started')

    op.drop_table('backup_records')
