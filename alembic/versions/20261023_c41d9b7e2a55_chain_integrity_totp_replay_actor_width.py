"""TOTP replay counter, wider actor columns

Revision ID: c41d9b7e2a55
Revises: 95936aa8afb2
Create Date: 2026-10-23 21:30:00+00:00

- users.totp_last_counter: the last accepted TOTP time step, so a code is never accepted twice.
- asset_authorizations.authorized_by, agent_runs.created_by, eval_runs.created_by,
  investigations.created_by: 36 -> 64 characters. API-key principals act as api_key:<uuid>
  (44 characters), which PostgreSQL rejected.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = 'c41d9b7e2a55'
down_revision: Union[str, None] = '95936aa8afb2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_WIDENED = (('asset_authorizations', 'authorized_by', False), ('agent_runs', 'created_by', True),
            ('eval_runs', 'created_by', True), ('investigations', 'created_by', True))


def upgrade() -> None:
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('totp_last_counter', sa.Integer(), nullable=False, server_default='0'))
    for table, column, has_default in _WIDENED:
        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.alter_column(column, existing_type=sa.String(length=36), type_=sa.String(length=64), existing_nullable=False,
                                  existing_server_default=None if not has_default else None)


def downgrade() -> None:
    for table, column, _ in reversed(_WIDENED):
        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.alter_column(column, existing_type=sa.String(length=64), type_=sa.String(length=36), existing_nullable=False)
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('totp_last_counter')
