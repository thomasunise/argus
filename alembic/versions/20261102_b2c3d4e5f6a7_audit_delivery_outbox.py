"""Persist audit mirror obligations so sink outages can be retried.

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
"""
from alembic import op
import sqlalchemy as sa

revision = 'b2c3d4e5f6a7'
down_revision = 'a1b2c3d4e5f6'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'audit_sink_deliveries',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('entry_id', sa.Integer(), nullable=False),
        sa.Column('tenant_id', sa.String(length=36), nullable=False),
        sa.Column('sink', sa.String(length=32), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('attempts', sa.Integer(), nullable=False),
        sa.Column('last_error', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_audit_sink_deliveries_pending', 'audit_sink_deliveries', ['status', 'id'])
    op.create_index('ux_audit_sink_deliveries_entry_sink', 'audit_sink_deliveries', ['entry_id', 'sink'], unique=True)
    op.create_index('ix_audit_sink_deliveries_tenant_id', 'audit_sink_deliveries', ['tenant_id'])


def downgrade():
    op.drop_table('audit_sink_deliveries')
