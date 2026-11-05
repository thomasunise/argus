import pytest
from app.api.deps import RateLimiter
from app.core.errors import RateLimited, Unavailable


class MemoryRedis:
    """In-memory stand-in implementing the sliding-window Lua contract."""

    def __init__(self):
        self.keys = {}
        self.now_ms = 1_700_000_000_000

    def eval(self, lua, nkeys, key, now_ms, window_ms, member, limit):
        now_ms, window_ms = int(now_ms), int(window_ms)
        hits = [ts for ts in self.keys.get(key, []) if ts > now_ms - window_ms]
        if len(hits) >= int(limit):
            self.keys[key] = hits
            return len(hits) + 1
        hits.append(int(now_ms))
        self.keys[key] = hits
        return len(hits)


def test_distributed_rate_limiter_shared_bucket():
    fake = MemoryRedis()
    a, b = RateLimiter(), RateLimiter()
    a._redis, b._redis = fake, fake
    a.check('tenant:abc', 2)
    b.check('tenant:abc', 2)
    with pytest.raises(RateLimited):
        a.check('tenant:abc', 2)
    assert all('tenant:abc' not in key for key in fake.keys)


def test_distributed_rate_limiter_window_slides(monkeypatch):
    import app.api.deps as deps

    fake = MemoryRedis()
    limiter = RateLimiter()
    limiter._redis = fake
    clock = {'now': 1_700_000_000.0}
    monkeypatch.setattr(deps.time, 'time', lambda: clock['now'])
    limiter.check('tenant:slide', 1, window=60.0)
    with pytest.raises(RateLimited):
        limiter.check('tenant:slide', 1, window=60.0)
    clock['now'] += 61.0
    limiter.check('tenant:slide', 1, window=60.0)  # the first hit has slid out


def test_rate_limiter_fails_closed_on_redis_error():
    class BrokenRedis:
        def eval(self, *args):
            raise ConnectionError('Redis unavailable')
    limiter = RateLimiter()
    limiter._redis = BrokenRedis()
    with pytest.raises(Unavailable):
        limiter.check('test', 10)
