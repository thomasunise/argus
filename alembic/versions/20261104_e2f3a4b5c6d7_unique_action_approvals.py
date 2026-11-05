"""Reject duplicate human approvals at the database layer.

Revision ID: e2f3a4b5c6d7
Revises: d1e2f3a4b5c6
"""
from alembic import op

revision = 'e2f3a4b5c6d7'
down_revision = 'd1e2f3a4b5c6'
branch_labels = None
depends_on = None


def upgrade():
    op.create_index('uq_action_approvals_actor', 'action_approvals', ['request_id', 'approver_id'], unique=True)


def downgrade():
    op.drop_index('uq_action_approvals_actor', table_name='action_approvals')
