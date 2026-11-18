"""Enterprise readiness Phase 2 schema additions: WebAuthn, API key expiry/IPs, cooling-off creator tracking, audit context and outbox.

Revision ID: 09a1b2c3d4e5
Revises: f3a4b5c6d7e8
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = '09a1b2c3d4e5'
down_revision = 'f3a4b5c6d7e8'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('users', sa.Column('must_change_password', sa.Boolean(), nullable=False, server_default=sa.text('false')))
    op.add_column('users', sa.Column('totp_enrollment_token_hash', sa.String(length=64), nullable=False, server_default=''))
    op.add_column('users', sa.Column('created_by', sa.String(length=36), nullable=False, server_default=''))

    op.add_column('memberships', sa.Column('permissions_json', sa.Text(), nullable=False, server_default='[]'))
    op.add_column('memberships', sa.Column('created_by', sa.String(length=36), nullable=False, server_default=''))

    op.add_column('api_keys', sa.Column('allowed_ips', sa.String(length=512), nullable=False, server_default=''))
    op.add_column('api_keys', sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True))

    op.create_table(
        'webauthn_credentials',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('credential_id', sa.String(length=256), nullable=False),
        sa.Column('public_key', sa.Text(), nullable=False),
        sa.Column('sign_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('name', sa.String(length=120), nullable=False, server_default='Security Key'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('credential_id'),
    )
    op.create_index('ix_webauthn_credentials_user_id', 'webauthn_credentials', ['user_id'])
    op.create_index('ix_webauthn_credentials_credential_id', 'webauthn_credentials', ['credential_id'], unique=True)

    op.add_column('audit', sa.Column('source_ip', sa.String(length=64), nullable=False, server_default=''))
    op.add_column('audit', sa.Column('user_agent', sa.String(length=256), nullable=False, server_default=''))
    op.add_column('audit', sa.Column('session_id', sa.String(length=64), nullable=False, server_default=''))

    op.create_table(
        'audit_outbox',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=36), nullable=False, server_default=''),
        sa.Column('entry_id', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('sink_name', sa.String(length=32), nullable=False),
        sa.Column('payload_json', sa.Text(), nullable=False),
        sa.Column('attempts', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('last_error', sa.String(length=500), nullable=False, server_default=''),
        sa.Column('next_attempt_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('delivered_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_audit_outbox_tenant_id', 'audit_outbox', ['tenant_id'])
    op.create_index('ix_audit_outbox_entry_id', 'audit_outbox', ['entry_id'])
    op.create_index('ix_audit_outbox_pending', 'audit_outbox', ['delivered_at', 'next_attempt_at'])


def downgrade():
    op.drop_index('ix_audit_outbox_pending', table_name='audit_outbox')
    op.drop_index('ix_audit_outbox_entry_id', table_name='audit_outbox')
    op.drop_index('ix_audit_outbox_tenant_id', table_name='audit_outbox')
    op.drop_table('audit_outbox')

    op.drop_column('audit', 'session_id')
    op.drop_column('audit', 'user_agent')
    op.drop_column('audit', 'source_ip')

    op.drop_index('ix_webauthn_credentials_credential_id', table_name='webauthn_credentials')
    op.drop_index('ix_webauthn_credentials_user_id', table_name='webauthn_credentials')
    op.drop_table('webauthn_credentials')

    op.drop_column('api_keys', 'expires_at')
    op.drop_column('api_keys', 'allowed_ips')

    op.drop_column('memberships', 'created_by')
    op.drop_column('memberships', 'permissions_json')

    op.drop_column('users', 'created_by')
    op.drop_column('users', 'totp_enrollment_token_hash')
    op.drop_column('users', 'must_change_password')
