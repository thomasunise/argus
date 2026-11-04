from __future__ import annotations

import asyncio
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import TYPE_CHECKING, Iterator, TypeVar

from sqlalchemy import create_engine, event, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.sql import Select

from ..models import Base
from .config import Settings

if TYPE_CHECKING:
    from .rbac import Principal

M = TypeVar('M')

# Request and queue-job boundaries supply this value; ordinary unscoped sessions do not.
_active_tenant: ContextVar[str | None] = ContextVar('argus_active_tenant', default=None)


def enter_tenant(tenant_id: str):
    if not tenant_id:
        raise ValueError('tenant_id is required')
    return _active_tenant.set(tenant_id)


def leave_tenant(token) -> None:
    _active_tenant.reset(token)


@event.listens_for(Session, 'after_begin')
def _rls_transaction_context(db: Session, transaction, connection) -> None:
    # SET LOCAL is transaction-scoped. Repeat it after each commit, not just at login.
    if transaction.nested or connection.dialect.name != 'postgresql':
        return
    tenant_id = db.info.get('tenant_id') or _active_tenant.get()
    if tenant_id:
        connection.execute(text("SELECT set_config('app.tenant_id', :tid, true)"), {'tid': tenant_id})


def assert_restricted_runtime_role(engine: Engine) -> None:
    """Production runtime DB role must not be superuser, BYPASSRLS or table owner."""
    if engine.dialect.name != 'postgresql':
        raise RuntimeError('production database must be PostgreSQL')
    with engine.connect() as conn:
        flags = conn.execute(text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname=current_user")).one()
        from ..models import Base
        unscoped_auth = {'api_keys', 'memberships', 'oidc_identities'}
        tables = {name for name, table in Base.metadata.tables.items()
                  if 'tenant_id' in table.columns and name not in unscoped_auth}
        rows = conn.execute(text("""
            SELECT c.relname, c.relrowsecurity,
                   pg_has_role(current_user, c.relowner, 'USAGE') AS can_act_as_owner
              FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = current_schema() AND c.relkind IN ('r', 'p')
        """)).all()
        state = {name: (enabled, owner) for name, enabled, owner in rows}
        policy_rows = conn.execute(text("""
            SELECT tablename, policyname, qual, with_check
              FROM pg_policies WHERE schemaname = current_schema()
        """)).all()
        policies = {}
        for table, policy, qual, check in policy_rows:
            policies.setdefault(table, []).append((policy, qual or '', check or ''))
        unsafe = []
        for name in sorted(tables):
            if name not in state or not state[name][0] or state[name][1]:
                unsafe.append(name)
                continue
            # The legacy policy enabled RLS but explicitly allowed NULL/empty
            # tenant contexts. Require the strict migration's USING + WITH CHECK.
            found = policies.get(name, [])
            if len(found) != 1 or found[0][0] != 'tenant_isolation_policy':
                unsafe.append(name)
                continue
            qual, check = found[0][1].lower(), found[0][2].lower()
            if any('tenant_id' not in part or 'nullif(' not in part
                   or 'current_setting(' not in part for part in (qual, check)):
                unsafe.append(name)
        if any(flags) or unsafe:
            raise RuntimeError('Production DATABASE_URL must use non-owner/non-BYPASSRLS credentials '
                               'and every tenant table must have RLS enabled; unsafe tables: '
                               + ', '.join(unsafe[:20]))



def make_engine(settings: Settings) -> Engine:
    url = settings.database_url
    if url.startswith('sqlite'):
        path = url.replace('sqlite:///', '')
        if path and path != ':memory:':
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        engine = create_engine(url, connect_args={'check_same_thread': False, 'timeout': 30}, future=True)

        @event.listens_for(engine, 'connect')
        def _pragmas(dbapi_connection, _):
            cursor = dbapi_connection.cursor()
            cursor.execute('PRAGMA foreign_keys=ON')
            cursor.execute('PRAGMA journal_mode=WAL')
            cursor.execute('PRAGMA busy_timeout=30000')
            cursor.close()

        return engine
    if not settings.is_production:
        return create_engine(url, pool_pre_ping=True, pool_size=2, max_overflow=5, pool_timeout=15, future=True)
    return create_engine(url, pool_pre_ping=True, pool_size=10, max_overflow=20, future=True)


class TenantSession(Session):
    """Inherit the authenticated job tenant for ALL sessions, not only session_scope."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        tenant_id = _active_tenant.get()
        if tenant_id:
            self.info['tenant_id'] = tenant_id


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, class_=TenantSession, expire_on_commit=False, autoflush=False, future=True)


def init_db(engine: Engine, settings: Settings) -> None:
    """Create tables for SQLite/dev. Production uses Alembic migrations (see alembic/)."""
    if settings.db_auto_create:
        Base.metadata.create_all(engine)


@contextmanager
def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    db = factory()
    tenant_id = _active_tenant.get()
    if tenant_id:
        db.info['tenant_id'] = tenant_id
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def scoped(model: type[M], principal: 'Principal | str') -> Select:
    """Tenant-scoped select. Accepts a Principal or a tenant id."""
    tenant_id = principal if isinstance(principal, str) else principal.tenant_id
    return select(model).where(model.tenant_id == tenant_id)  # type: ignore[attr-defined]


def get_scoped(db: Session, model: type[M], principal: 'Principal | str', object_id: str) -> M | None:
    tenant_id = principal if isinstance(principal, str) else principal.tenant_id
    return db.execute(select(model).where(model.id == object_id, model.tenant_id == tenant_id)).scalar_one_or_none()  # type: ignore[attr-defined]


def set_tenant_context(db: Session, tenant_id: str | None) -> None:
    """Bind the active tenant ID to the session and, on PostgreSQL, set `app.tenant_id` for RLS."""
    tid = str(tenant_id or '')
    if not tid:
        raise ValueError('tenant ID cannot be empty for an RLS session')
    old_tenant = db.info.get('tenant_id')
    if old_tenant and old_tenant != tid:
        raise ValueError('tenant cannot be switched on an existing DB session')
    db.info['tenant_id'] = tid
    bind = db.get_bind()
    if bind is not None and bind.dialect.name == 'postgresql':
        db.execute(text("SELECT set_config('app.tenant_id', :tid, true)"), {'tid': tid})


_TOKEN_ROUTES = {
    'canary': text('SELECT public.argus_route_canary(:token)'),
    'oob': text('SELECT public.argus_route_oob(:token)'),
    'slack': text('SELECT public.argus_route_slack(:token)'),
    'integration': text('SELECT public.argus_route_integration(:token)'),
}


def bind_public_token_tenant(db: Session, kind: str, token: str, *, production: bool) -> bool:
    """Resolve only a high-entropy callback token before applying the RLS tenant.

    Production PostgreSQL uses migration-owned SECURITY DEFINER functions that
    disclose only tenant_id for the exact token; raw table scans cannot bypass
    RLS. SQLite/development retains its existing direct lookup behavior.
    """
    if not token:
        return False
    if not production or db.get_bind().dialect.name != 'postgresql':
        return True
    query = _TOKEN_ROUTES.get(kind)
    if query is None:
        raise ValueError('unsupported public token kind')
    tenant_id = db.execute(query, {'token': token}).scalar_one_or_none()
    if not tenant_id:
        return False
    set_tenant_context(db, tenant_id)
    return True


def pool_stats(engine: Engine) -> dict[str, int | str]:
    """Return connection pool telemetry for health and monitoring endpoints."""
    pool = getattr(engine, 'pool', None)
    if pool is None:
        return {'dialect': engine.dialect.name}
    stats: dict[str, int | str] = {'dialect': engine.dialect.name, 'pool_class': type(pool).__name__}
    for attr, key in (('size', 'size'), ('checkedin', 'checked_in'), ('checkedout', 'checked_out'), ('overflow', 'overflow')):
        fn = getattr(pool, attr, None)
        if callable(fn):
            try:
                stats[key] = int(fn())
            except Exception:
                pass
    return stats


class CommitBeforeResponseMiddleware:
    """Pure ASGI middleware: commits the request's database session (request.state.db) before the
    first response byte leaves, so a client that reads immediately after a write sees it. The
    get_db dependency still commits on teardown as a no-op safety net."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message):
            if message['type'] == 'http.response.start' and 200 <= message.get('status', 500) < 400:
                session = scope.get('state', {}).get('db')
                if session is not None and session.is_active:
                    await asyncio.to_thread(session.commit)
            await send(message)

        await self.app(scope, receive, send_wrapper)
