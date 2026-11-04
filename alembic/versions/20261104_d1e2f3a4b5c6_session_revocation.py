"""Persist server-side invalidation of browser sessions.

Revision ID: d1e2f3a4b5c6
Revises: c7b2a19e604f
"""
from alembic import op
import sqlalchemy as sa

revision = 'd1e2f3a4b5c6'
down_revision = 'c7b2a19e604f'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('users', sa.Column('sessions_invalidated_at', sa.DateTime(timezone=True), nullable=True))


def downgrade():
    op.drop_column('users', 'sessions_invalidated_at')
