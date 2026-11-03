"""Serialize distinct action approvals across API replicas.

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
"""
from alembic import op

revision = 'c3d4e5f6a7b8'
down_revision = 'b2c3d4e5f6a7'
branch_labels = None
depends_on = None


def upgrade():
    # Existing duplicates must be investigated, not silently deleted.
    op.create_index('ux_action_approvals_request_actor', 'action_approvals',
                    ['request_id', 'approver_id'], unique=True)
    op.drop_index('ix_action_approvals_request', table_name='action_approvals')


def downgrade():
    op.create_index('ix_action_approvals_request', 'action_approvals', ['request_id', 'approver_id'])
    op.drop_index('ux_action_approvals_request_actor', table_name='action_approvals')
