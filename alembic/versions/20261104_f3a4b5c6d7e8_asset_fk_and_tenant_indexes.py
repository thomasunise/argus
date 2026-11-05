"""Align asset foreign-key deletion semantics and tenant indexes with SQLAlchemy models.

Revision ID: f3a4b5c6d7e8
Revises: e2f3a4b5c6d7

PostgreSQL Alembic drift detection found old RESTRICT/NO ACTION constraints
where models require CASCADE or SET NULL. Also add the missing tenant indexes.
"""
from __future__ import annotations

from alembic import op

revision = 'f3a4b5c6d7e8'
down_revision = 'e2f3a4b5c6d7'
branch_labels = None
depends_on = None

ASSET_FKS = {
    'asset_authorizations': 'CASCADE',
    'asset_credentials': 'CASCADE',
    'events': 'SET NULL',
    'findings': 'SET NULL',
    'oob_tokens': 'CASCADE',
}
TENANT_INDEXES = ('oob_tokens', 'pentest_hypotheses', 'pentest_runs')


def upgrade():
    if op.get_bind().dialect.name != 'postgresql':
        return
    for table, ondelete in ASSET_FKS.items():
        op.drop_constraint(f'{table}_asset_id_fkey', table, type_='foreignkey')
        op.create_foreign_key(f'{table}_asset_id_fkey', table, 'assets',
                              ['asset_id'], ['id'], ondelete=ondelete)
    for table in TENANT_INDEXES:
        op.create_index(f'ix_{table}_tenant_id', table, ['tenant_id'])


def downgrade():
    if op.get_bind().dialect.name != 'postgresql':
        return
    for table in reversed(TENANT_INDEXES):
        op.drop_index(f'ix_{table}_tenant_id', table_name=table)
    for table in reversed(tuple(ASSET_FKS)):
        op.drop_constraint(f'{table}_asset_id_fkey', table, type_='foreignkey')
        op.create_foreign_key(f'{table}_asset_id_fkey', table, 'assets', ['asset_id'], ['id'])
