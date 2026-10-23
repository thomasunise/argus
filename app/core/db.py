from __future__ import annotations

import asyncio
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Iterator, TypeVar

from sqlalchemy import create_engine, event, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.sql import Select

from ..models import Base
from .config import Settings

if TYPE_CHECKING:
    from .rbac import Principal

M = TypeVar('M')


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
    return create_engine(url, pool_pre_ping=True, pool_size=10, max_overflow=20, future=True)


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, autoflush=False, future=True)


def init_db(engine: Engine, settings: Settings) -> None:
    """Create tables for SQLite/dev. Production uses Alembic migrations (see alembic/)."""
    if settings.db_auto_create:
        Base.metadata.create_all(engine)


@contextmanager
def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    db = factory()
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
