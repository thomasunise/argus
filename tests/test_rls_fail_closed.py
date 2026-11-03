"""RLS regression under an actual unprivileged PostgreSQL role."""
import uuid
import pytest

def test_postgres_rls_is_deny_by_default_for_nonowner(app, client):
    """Direct SQL without tenant context must see no assets and cannot insert.

    This test is skipped for SQLite because SQLite has no PostgreSQL RLS.
    It uses a temporary non-owner role; the service's migration user is not
    an appropriate account to use when evaluating RLS effectiveness.
    """
    engine_db = app.state.engine
    if engine_db.dialect.name != 'postgresql':
        pytest.skip('requires PostgreSQL RLS')
    from sqlalchemy import text
    from app.models import Asset
    # The shared PostgreSQL pytest fixture creates tables directly from ORM
    # metadata (not Alembic); install the same RLS policy explicitly here.
    with engine_db.begin() as c:
        c.execute(text('ALTER TABLE public.assets ENABLE ROW LEVEL SECURITY'))
        c.execute(text('DROP POLICY IF EXISTS tenant_isolation_policy ON public.assets'))
        c.execute(text(
            'CREATE POLICY tenant_isolation_policy ON public.assets '
            "USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')) "
            "WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), ''))"))
    seed = Asset(tenant_id=app.state.default_tenant_id, name='P0 RLS sentinel',
                 kind='web', target='https://p0-rls.invalid', environment='lab')
    with app.state.db_factory() as db:
        db.add(seed)
        db.commit()
    role = 'argus_p0_' + uuid.uuid4().hex[:12]
    with engine_db.begin() as c:
        c.execute(text(f'CREATE ROLE "{role}" NOLOGIN'))
        c.execute(text(f'GRANT USAGE ON SCHEMA public TO "{role}"'))
        c.execute(text(f'GRANT SELECT, INSERT, UPDATE ON public.assets TO "{role}"'))
    try:
        with engine_db.begin() as c:
            c.execute(text(f'SET LOCAL ROLE "{role}"'))
            assert c.execute(text('SELECT COUNT(*) FROM public.assets')).scalar_one() == 0
            from sqlalchemy.exc import DBAPIError
            with pytest.raises(DBAPIError):
                with c.begin_nested():
                    c.execute(text("INSERT INTO public.assets (id, tenant_id, name, kind, target) "
                                   "VALUES ('p0-blocked', 'unknown', 'blocked', 'web', 'https://example.test')"))
            # An explicit tenant context is the only way to see tenant rows.
            c.execute(text("SELECT set_config('app.tenant_id', :tid, true)"), {'tid': app.state.default_tenant_id})
            assert c.execute(text('SELECT COUNT(*) FROM public.assets')).scalar_one() >= 1
            # WITH CHECK blocks transferring an existing row to a different tenant.
            with pytest.raises(DBAPIError):
                with c.begin_nested():
                    c.execute(text('UPDATE public.assets SET tenant_id = :other WHERE id = :id'),
                              {'other': 'different-tenant', 'id': seed.id})
        # SET LOCAL must be reapplied after commit, without leaking across connections.
        with engine_db.connect() as conn:
            conn.execute(text(f'SET ROLE "{role}"'))
            conn.commit()
            try:
                from sqlalchemy.orm import Session
                from app.core.db import set_tenant_context
                with Session(bind=conn) as scoped_session:
                    assert scoped_session.execute(text('SELECT COUNT(*) FROM public.assets')).scalar_one() == 0
                    scoped_session.commit()
                    set_tenant_context(scoped_session, app.state.default_tenant_id)
                    assert scoped_session.execute(text('SELECT COUNT(*) FROM public.assets')).scalar_one() >= 1
                    scoped_session.commit()
                    assert scoped_session.execute(text('SELECT COUNT(*) FROM public.assets')).scalar_one() >= 1
                    with pytest.raises(ValueError, match='cannot be switched'):
                        set_tenant_context(scoped_session, 'other-tenant')
            finally:
                conn.execute(text('RESET ROLE'))
                conn.commit()
    finally:
        with engine_db.begin() as c:
            c.execute(text(f'REVOKE ALL ON public.assets FROM "{role}"'))
            c.execute(text(f'REVOKE ALL ON SCHEMA public FROM "{role}"'))
            c.execute(text(f'DROP ROLE "{role}"'))
        with app.state.db_factory() as db:
            existing = db.get(Asset, seed.id)
            if existing is not None:
                db.delete(existing)
                db.commit()
