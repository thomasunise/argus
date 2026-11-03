"""Re-apply fail-closed RLS policies to existing PostgreSQL databases.

Revision ID: b6a4f37c9120
Revises: a1b2c3d4e5f6

IMPORTANT: application connection must be a non-owner, non-BYPASSRLS role.
The migration role retains ownership and privileges to manage the schema.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = 'b6a4f37c9120'
down_revision = 'a1b2c3d4e5f6'
branch_labels = None
depends_on = None

# Auth and membership records are resolved before an authenticated tenant exists.
# They require a separate identity-access design before enabling RLS on them.
IDENTITY_TABLES = frozenset({'api_keys', 'memberships', 'oidc_identities'})


def _tenant_tables(bind):
    inspector = sa.inspect(bind)
    return sorted(name for name in inspector.get_table_names()
                  if name not in IDENTITY_TABLES
                  and 'tenant_id' in {col['name'] for col in inspector.get_columns(name)})


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != 'postgresql':
        return
    for table in _tenant_tables(bind):
        op.execute(sa.text(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY'))
        op.execute(sa.text(f'DROP POLICY IF EXISTS tenant_isolation_policy ON "{table}"'))
        op.execute(sa.text(
            f'CREATE POLICY tenant_isolation_policy ON "{table}" '
            "USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')) "
            "WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))"
        ))


def downgrade() -> None:
    # A downgrade must never silently restore the former fail-open policy.
    raise RuntimeError('Refusing to downgrade fail-closed tenant isolation')
