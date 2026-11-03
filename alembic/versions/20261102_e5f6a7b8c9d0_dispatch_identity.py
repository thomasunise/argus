"""Persist the original action dispatch authorization for safe queue recovery.

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
"""
from alembic import op
import sqlalchemy as sa

revision = 'e5f6a7b8c9d0'
down_revision = 'd4e5f6a7b8c9'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('action_runs', sa.Column('dispatch_payload_json', sa.Text(), nullable=False, server_default='{}'))
    op.add_column('action_runs', sa.Column('rollback_dispatch_json', sa.Text(), nullable=False, server_default='{}'))


def downgrade():
    op.drop_column('action_runs', 'rollback_dispatch_json')
    op.drop_column('action_runs', 'dispatch_payload_json')
