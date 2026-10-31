from app.api.deps import RateLimiter
from app.core.errors import RateLimited, Unavailable
import pytest


class MemoryRedis:
    def __init__(self):
        self.keys = {}

    def eval(self, lua, nkeys, key, expire_ms):
        self.keys[key] = self.keys.get(key, 0) + 1
        return self.keys[key]


def test_distributed_rate_limiter_shared_bucket():
    fake = MemoryRedis()
    a, b = RateLimiter(), RateLimiter()
    a._redis, b._redis = fake, fake
    a.check('tenant:abc', 2)
    b.check('tenant:abc', 2)
    with pytest.raises(RateLimited):
        a.check('tenant:abc', 2)
    assert all('tenant:abc' not in key for key in fake.keys)


def test_rate_limiter_fails_closed_on_redis_error():
    class BrokenRedis:
        def eval(self, *args):
            raise ConnectionError('Redis unavailable')
    limiter = RateLimiter()
    limiter._redis = BrokenRedis()
    with pytest.raises(Unavailable):
        limiter.check('test', 10)
