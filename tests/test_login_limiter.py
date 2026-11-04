"""Redis-backed authentication throttle regression, including cross-replica behavior."""
from __future__ import annotations

import pytest

from app.core.errors import RateLimited, Unavailable
from app.core.login_limiter import LoginFailureLimiter


class FakeRedis:
    """Minimal atomic Redis scripting stand-in, shared by two app instances."""

    def __init__(self):
        self.items = {}

    def eval(self, script, keys_count, key, *args):
        assert keys_count == 1
        if 'ZADD' in script:
            self.items.setdefault(key, set()).add(args[-1])
        return len(self.items.get(key, set()))

    def delete(self, *keys):
        for key in keys:
            self.items.pop(key, None)


def test_failed_auth_throttle_is_shared_across_replicas():
    redis = FakeRedis()
    first, second = LoginFailureLimiter(), LoginFailureLimiter()
    first._redis = second._redis = redis
    keys = ('ip:127.0.0.1', 'account:alice@example.test')
    for _ in range(3):
        first.record(keys, 300)
    with pytest.raises(RateLimited):
        second.check(keys, 3, 300)
    first.clear(keys)
    second.check(keys, 3, 300)
    assert all('alice@example.test' not in key for key in redis.items)


def test_failed_auth_throttle_is_fail_closed():
    class BrokenRedis:
        def eval(self, *args):
            raise ConnectionError('redis unavailable')
        def delete(self, *args):
            raise ConnectionError('redis unavailable')

    limiter = LoginFailureLimiter()
    limiter._redis = BrokenRedis()
    with pytest.raises(Unavailable):
        limiter.check(('account:alice',), 8, 300)
    with pytest.raises(Unavailable):
        limiter.record(('account:alice',), 300)
    with pytest.raises(Unavailable):
        limiter.clear(('account:alice',))
