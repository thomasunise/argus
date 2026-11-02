"""Integration checks for non-owner PostgreSQL row-level security."""
from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import text

from app.core.db import set_tenant_context
from app.models import Asset


def test_tenant_context_is_restored_after_commit(db, default_tenant_id):
    if db.get_bind().dialect.name != 'postgresql':
        pytest.skip('PostgreSQL only')
    set_tenant_context(db, default_tenant_id)
    db.commit()
    observed = db.scalar(text("SELECT current_setting('app.tenant_id', true)"))
    assert observed == default_tenant_id
    db.commit()
    assert db.scalar(text("SELECT current_setting('app.tenant_id', true)")) == default_tenant_id


def test_unprivileged_role_cannot_read_unset_or_foreign_tenant(db, app, default_tenant_id):
    if db.get_bind().dialect.name != 'postgresql':
        pytest.skip('PostgreSQL only')

    # The CI PostgreSQL account is the migration owner/superuser. Assume an
    # unprivileged role to test that RLS actually stops unauthorized SELECTs.
    role = 'argus_rls_test_' + uuid4().hex[:10]
    engine = app.state.engine
    with engine.begin() as admin:
        admin.execute(text(f'CREATE ROLE "{role}" NOLOGIN NOBYPASSRLS'))
        admin.execute(text(f'GRANT USAGE ON SCHEMA public TO "{role}"'))
        admin.execute(text(f'GRANT SELECT ON TABLE assets TO "{role}"'))
    try:
        mine = Asset(tenant_id=default_tenant_id, name='rls-owned', kind='host', target='rls-owned.example', environment='staging')
        foreign = Asset(tenant_id=str(uuid4()), name='rls-foreign', kind='host', target='rls-foreign.example', environment='staging')
        db.add_all([mine, foreign])
        db.commit()

        with engine.connect() as conn:
            conn.execute(text(f'SET ROLE "{role}"'))
            assert conn.scalar(text('SELECT count(*) FROM assets')) == 0
            conn.execute(text("SELECT set_config('app.tenant_id', :tid, true)"), {'tid': default_tenant_id})
            assert conn.scalar(text('SELECT count(*) FROM assets')) >= 1
            assert conn.scalar(text("SELECT count(*) FROM assets WHERE name='rls-foreign'")) == 0
            conn.rollback()
    finally:
        with engine.begin() as admin:
            admin.execute(text(f'DROP OWNED BY "{role}"'))
            admin.execute(text(f'DROP ROLE "{role}"'))
