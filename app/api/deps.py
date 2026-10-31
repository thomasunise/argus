"""FastAPI dependencies: database session, settings, principal resolution, permission checks."""
from __future__ import annotations

import hashlib
import secrets
import time
from collections import defaultdict, deque
from typing import Iterator

from fastapi import Depends, Header, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.config import Settings
from ..core.errors import Forbidden, RateLimited, Unauthorized
from ..core.rbac import Principal, Role, has
from ..core.security import hash_api_key, parse_api_key
from ..models import ApiKey, Membership, Tenant, User, utcnow

SAFE_METHODS = {'GET', 'HEAD', 'OPTIONS'}


async def write_off_loop(db: Session, fn) -> None:
    """Run DB writes from an async endpoint in a thread, then commit.

    An async endpoint that writes on the event loop after an await can deadlock with the in-process worker on
    SQLite: the worker holds the write lock while it waits for the loop, and the endpoint blocks the loop while it
    waits for the lock. Writing in a thread keeps the loop free, and committing releases the lock straight away.
    """
    from starlette.concurrency import run_in_threadpool

    def _run() -> None:
        fn()
        db.commit()

    await run_in_threadpool(_run)


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_db(request: Request) -> Iterator[Session]:
    db = request.app.state.db_factory()
    request.state.db = db
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


class RateLimiter:
    """Bounded in-process limiter, or Redis-backed atomic limiter when configured.

    Production with Redis enabled fails closed if the shared limiter is unavailable.
    A separate edge limiter is still recommended for anonymous traffic.
    """
    REDIS_SCRIPT = """
local n = redis.call('INCR', KEYS[1])
if n == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
return n
"""

    def __init__(self, redis_url: str = ''):
        self._hits: dict[str, deque] = defaultdict(deque)
        self._checks = 0
        self._redis = None
        if redis_url:
            import redis
            self._redis = redis.Redis.from_url(redis_url, socket_connect_timeout=0.5,
                                                socket_timeout=0.5, decode_responses=True)

    def _sweep(self, now: float) -> None:
        """Drop idle buckets so unauthenticated endpoints (canary hits) cannot grow memory without bound."""
        for key in [k for k, b in self._hits.items() if not b or now - b[-1] > 600]:
            del self._hits[key]

    def check(self, key: str, limit: int, window: float = 60.0) -> None:
        if self._redis is not None:
            hashed = hashlib.sha256(key.encode('utf-8')).hexdigest()
            # Fixed window from the first accepted hit, executed atomically on all workers.
            try:
                seen = int(self._redis.eval(self.REDIS_SCRIPT, 1,
                                           'argus:rate:' + hashed, max(1, int(window * 1000))))
            except Exception as exc:
                from ..core.errors import Unavailable
                raise Unavailable('Distributed rate limiter is unavailable') from exc
            if seen > limit:
                raise RateLimited('Rate limit exceeded')
            return
        now = time.monotonic()
        self._checks += 1
        if self._checks % 1000 == 0 or len(self._hits) > 50000:
            self._sweep(now)
        bucket = self._hits[key]
        while bucket and now - bucket[0] > window:
            bucket.popleft()
        if len(bucket) >= limit:
            raise RateLimited('Rate limit exceeded')
        bucket.append(now)


def _principal_from_api_key(db: Session, raw: str, request: Request) -> Principal | None:
    prefix = parse_api_key(raw)
    if not prefix:
        return None
    key = db.execute(select(ApiKey).where(ApiKey.prefix == prefix, ApiKey.revoked_at.is_(None))).scalar_one_or_none()
    if not key or not secrets.compare_digest(key.key_hash, hash_api_key(raw)):
        return None
    tenant = db.get(Tenant, key.tenant_id)
    if not tenant or not tenant.is_active:
        return None
    key.last_used_at = utcnow()
    scopes = frozenset(s.strip() for s in key.scopes.split(',') if s.strip())
    return Principal(tenant_id=key.tenant_id, role=Role(key.role), auth='api_key', api_key_id=key.id, scopes=scopes,
                     email=f'api-key:{key.name}', request_id=getattr(request.state, 'request_id', ''))


def _principal_from_session(db: Session, request: Request, settings: Settings) -> Principal | None:
    session = request.session
    user_id, tenant_id = session.get('user_id'), session.get('tenant_id')
    if not user_id or not tenant_id or session.get('authed') is not True:
        return None
    if settings.totp_required and not session.get('mfa'):
        return None
    issued_at = session.get('issued_at')
    if not isinstance(issued_at, (int, float)) or time.time() - issued_at > settings.session_absolute_max_age:
        return None  # absolute lifetime: a refreshed cookie cannot be kept alive forever
    user = db.get(User, user_id)
    if not user or not user.is_active:
        return None
    tenant = db.get(Tenant, tenant_id)
    if not tenant or not tenant.is_active:
        return None
    membership = db.execute(select(Membership).where(Membership.user_id == user_id, Membership.tenant_id == tenant_id)).scalar_one_or_none()
    if not membership:
        return None
    return Principal(tenant_id=tenant_id, role=Role(membership.role), auth='session', user_id=user.id, email=user.email,
                     request_id=getattr(request.state, 'request_id', ''))


def current_principal(request: Request, db: Session = Depends(get_db), settings: Settings = Depends(get_settings),
                      x_api_key: str = Header(default=''), authorization: str = Header(default='')) -> Principal | None:
    raw = x_api_key or (authorization[7:] if authorization.lower().startswith('bearer ') else '')
    if raw:
        principal = _principal_from_api_key(db, raw, request)
        if principal is None:
            raise Unauthorized('Invalid API key')
        request.state.principal = principal
        return principal
    principal = _principal_from_session(db, request, settings)
    request.state.principal = principal
    return principal


def require(*perms: str):
    """Dependency factory. Enforces authentication, CSRF for session-authenticated mutations, and permissions."""

    def dependency(request: Request, principal: Principal | None = Depends(current_principal),
                   settings: Settings = Depends(get_settings)) -> Principal:
        if principal is None:
            raise Unauthorized('Authentication required')
        if principal.auth == 'session' and request.method not in SAFE_METHODS:
            given = request.headers.get('x-csrf-token', '')
            expected = request.session.get('csrf', '')
            if not expected or not secrets.compare_digest(given, expected):
                raise Forbidden('CSRF validation failed')
        for perm in perms:
            if not has(principal, perm):
                raise Forbidden(f'Missing permission {perm}')
        limiter: RateLimiter = request.app.state.rate_limiter
        limiter.check(f'api:{principal.tenant_id}:{principal.user_id or principal.api_key_id}', settings.api_rate_limit_per_minute)
        return principal

    return dependency


def require_scope(scope: str):
    """For API-key-only endpoints such as ingest: the key must carry the scope or be an operator+ key."""

    def dependency(request: Request, principal: Principal | None = Depends(current_principal),
                   settings: Settings = Depends(get_settings)) -> Principal:
        if principal is None or principal.auth != 'api_key':
            raise Unauthorized('API key required')
        if scope not in principal.scopes and not has(principal, f'{scope}:write') and principal.role not in {Role.operator, Role.admin, Role.owner}:
            raise Forbidden(f'API key lacks scope {scope}')
        limiter: RateLimiter = request.app.state.rate_limiter
        limiter.check(f'ingest:{principal.api_key_id}', settings.ingest_rate_limit_per_minute)
        return principal

    return dependency


class Page:
    """Cursor pagination helper: ?limit=&cursor= where cursor is an opaque offset."""

    def __init__(self, limit: int = 50, cursor: str | None = None):
        self.limit = max(1, min(500, limit))
        try:
            self.offset = max(0, min(int(cursor), 1_000_000)) if cursor else 0
        except ValueError:
            self.offset = 0

    def apply(self, stmt):
        return stmt.offset(self.offset).limit(self.limit + 1)

    def wrap(self, rows: list, serialize) -> dict:
        items = rows[: self.limit]
        next_cursor = str(self.offset + self.limit) if len(rows) > self.limit else None
        return {'items': [serialize(r) for r in items], 'next_cursor': next_cursor}
