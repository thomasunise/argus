"""Capability-restricted tenant lookup for unauthenticated security callbacks.

Revision ID: c7b2a19e604f
Revises: b6a4f37c9120

These read-only SECURITY DEFINER functions reveal only tenant IDs to callers
presenting a matching high-entropy callback token. They never return any tenant
data, credentials or event rows. Caller must establish SET LOCAL app.tenant_id
before reading the protected tables.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = 'c7b2a19e604f'
down_revision = 'b6a4f37c9120'
branch_labels = None
depends_on = None


FUNCTIONS = {
    'argus_route_canary': """SELECT tenant_id FROM public.canaries
        WHERE token = p_token OR (token <> lower(token) AND lower(token) = lower(p_token))
        LIMIT 1""",
    'argus_route_oob': """SELECT tenant_id FROM public.oob_tokens
        WHERE token = p_token LIMIT 1""",
    'argus_route_integration': """SELECT tenant_id FROM public.integration_configs
        WHERE id = p_token AND enabled IS TRUE LIMIT 1""",
    'argus_route_slack': """SELECT tenant_id FROM public.integration_configs
        WHERE id = p_token AND kind = 'slack' AND enabled IS TRUE LIMIT 1""",
}


def upgrade():
    bind = op.get_bind()
    if bind.dialect.name != 'postgresql':
        return
    for name, query in FUNCTIONS.items():
        # Function names are hardcoded above, not user input.
        op.execute(sa.text(
            f'CREATE OR REPLACE FUNCTION public.{name}(p_token text) RETURNS text '
            f'LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog '
            f'AS $argus$ {query} $argus$'
        ))


def downgrade():
    bind = op.get_bind()
    if bind.dialect.name != 'postgresql':
        return
    for name in FUNCTIONS:
        op.execute(sa.text(f'DROP FUNCTION IF EXISTS public.{name}(text)'))
