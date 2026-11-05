"""Distributed failed-authentication throttling.

Redis Lua uses server TIME, atomic rolling windows, and fail-closed behavior.
The in-memory path is development-only.
"""
from __future__ import annotations

import hashlib
import secrets
import time
from collections import defaultdict, deque

from .errors import RateLimited, Unavailable


class LoginFailureLimiter:
    CHECK = """
local t = redis.call('TIME')
local now = tonumber(t[1])*1000 + tonumber(t[2])/1000
redis.call('ZREMRANGEBYSCORE',KEYS[1],'-inf',now-tonumber(ARGV[1]))
return redis.call('ZCARD',KEYS[1])
"""
    RECORD = """
local t = redis.call('TIME')
local now = tonumber(t[1])*1000 + tonumber(t[2])/1000
redis.call('ZREMRANGEBYSCORE',KEYS[1],'-inf',now-tonumber(ARGV[1]))
redis.call('ZADD',KEYS[1],now,ARGV[2])
redis.call('PEXPIRE',KEYS[1],tonumber(ARGV[1]))
return redis.call('ZCARD',KEYS[1])
"""

    def __init__(self, redis_url: str = ''):
        self._redis = None
        self._local: dict[str, deque[float]] = defaultdict(deque)
        if redis_url:
            import redis
            self._redis = redis.Redis.from_url(redis_url, socket_connect_timeout=0.5,
                                                socket_timeout=0.5, decode_responses=True)

    @staticmethod
    def _key(key: str) -> str:
        return 'argus:auth:fail:' + hashlib.sha256(key.encode('utf-8')).hexdigest()

    def check(self, keys, limit: int, window_seconds: int) -> None:
        now = time.monotonic()
        for key in keys:
            if self._redis is not None:
                try:
                    raw_failures: object = self._redis.eval(self.CHECK, 1, self._key(key), str(max(1, int(window_seconds * 1000))))
                    failures = int(str(raw_failures))
                except Exception as exc:
                    raise Unavailable('Distributed login throttle is unavailable') from exc
            else:
                bucket = self._local[key]
                while bucket and now - bucket[0] >= window_seconds:
                    bucket.popleft()
                failures = len(bucket)
            if failures >= limit:
                raise RateLimited('Too many attempts, try again later')

    def record(self, keys, window_seconds: int) -> None:
        now = time.monotonic()
        for key in keys:
            if self._redis is not None:
                try:
                    self._redis.eval(self.RECORD, 1, self._key(key),
                                     str(max(1, int(window_seconds * 1000))), secrets.token_hex(12))
                except Exception as exc:
                    raise Unavailable('Distributed login throttle is unavailable') from exc
            else:
                self._local[key].append(now)
                if len(self._local) > 10000:
                    cutoff = now - window_seconds
                    for stale in [k for k,b in self._local.items() if not b or b[-1] < cutoff]:
                        del self._local[stale]

    def clear(self, keys) -> None:
        if self._redis is not None:
            try:
                self._redis.delete(*(self._key(key) for key in keys))
            except Exception as exc:
                raise Unavailable('Distributed login throttle is unavailable') from exc
        else:
            for key in keys:
                self._local.pop(key, None)
