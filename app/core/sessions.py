"""Server-side session store (Redis when configured, in-memory fallback for single-process dev/tests).

Keeps an opaque `sid` in the browser cookie and holds transient secrets (`pending_totp_secret`,
`oidc_verifier`, `oidc_state`, `oidc_nonce`, `webauthn_challenge`) and per-session revocation
state on the server so secrets never travel to the browser cookie.
"""
from __future__ import annotations

import json
import secrets
import time
from typing import Any


class ServerSessionStore:
    MAX_MEM_ENTRIES = 10_000

    def __init__(self, redis_url: str = '', ttl_seconds: int = 43200):
        self.ttl_seconds = max(60, int(ttl_seconds))
        self._mem: dict[str, tuple[float, dict[str, Any]]] = {}
        self._revoked: dict[str, float] = {}
        self._redis = None
        if redis_url:
            import redis

            self._redis = redis.Redis.from_url(redis_url, socket_connect_timeout=0.5, socket_timeout=0.5, decode_responses=True)

    def _key(self, sid: str) -> str:
        return f'argus:sess:{sid}'

    def _prune(self, now: float) -> None:
        if len(self._mem) >= self.MAX_MEM_ENTRIES:
            expired = [k for k, (exp, _) in self._mem.items() if exp <= now]
            for k in expired:
                self._mem.pop(k, None)
            while len(self._mem) >= self.MAX_MEM_ENTRIES:
                self._mem.pop(next(iter(self._mem)), None)
        if len(self._revoked) >= self.MAX_MEM_ENTRIES:
            expired_rev = [k for k, exp in self._revoked.items() if exp <= now]
            for k in expired_rev:
                self._revoked.pop(k, None)
            while len(self._revoked) >= self.MAX_MEM_ENTRIES:
                self._revoked.pop(next(iter(self._revoked)), None)

    def create(self, data: dict[str, Any], ttl: int | None = None) -> str:
        sid = secrets.token_urlsafe(32)
        self.set(sid, data, ttl=ttl)
        return sid

    def get(self, sid: str) -> dict[str, Any] | None:
        if not sid or self.is_revoked(sid):
            return None
        if self._redis is not None:
            raw = self._redis.get(self._key(sid))
            if not raw:
                return None
            try:
                parsed = json.loads(str(raw))
                return parsed if isinstance(parsed, dict) else None
            except ValueError:
                return None
        entry = self._mem.get(sid)
        if entry is None:
            return None
        expires_at, payload = entry
        if time.time() > expires_at:
            self._mem.pop(sid, None)
            return None
        return dict(payload)

    def set(self, sid: str, data: dict[str, Any], ttl: int | None = None) -> None:
        if not sid:
            return
        lifetime = max(60, int(ttl or self.ttl_seconds))
        if self._redis is not None:
            self._redis.set(self._key(sid), json.dumps(data, default=str), ex=lifetime)
            return
        now = time.time()
        self._prune(now)
        self._mem[sid] = (now + lifetime, dict(data))

    def update(self, sid: str, **fields: Any) -> dict[str, Any]:
        current = self.get(sid) or {}
        current.update(fields)
        self.set(sid, current)
        return current

    def pop_field(self, sid: str, field: str, default: Any = None) -> Any:
        if not sid:
            return default
        current = self.get(sid)
        if not current or field not in current:
            return default
        val = current.pop(field, default)
        self.set(sid, current)
        return val

    def revoke(self, sid: str) -> None:
        if not sid:
            return
        now = time.time()
        self._prune(now)
        self._revoked[sid] = now + self.ttl_seconds
        if self._redis is not None:
            self._redis.delete(self._key(sid))
        else:
            self._mem.pop(sid, None)

    def is_revoked(self, sid: str) -> bool:
        if not sid:
            return False
        exp = self._revoked.get(sid)
        if exp is None:
            return False
        if time.time() > exp:
            self._revoked.pop(sid, None)
            return False
        return True
