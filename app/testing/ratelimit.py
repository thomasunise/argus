"""Async token-bucket rate limiter, one bucket per (tenant, asset), honoring scope.max_rps.

In-process only (the API and in-process workers share one event loop). A production Redis
worker deployment would back this with a shared store; the interface stays the same.
"""
from __future__ import annotations

import asyncio
import time


class RateLimiter:
    """A simple async token bucket. Capacity equals one second of tokens (minimum 1)."""

    def __init__(self, rate_per_second: float):
        self.rate = max(0.1, float(rate_per_second))
        self.capacity = max(1.0, self.rate)
        self._tokens = self.capacity
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._updated
        if elapsed > 0:
            self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
            self._updated = now

    async def acquire(self, tokens: float = 1.0) -> None:
        async with self._lock:
            while True:
                self._refill()
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                deficit = tokens - self._tokens
                await asyncio.sleep(max(0.0, deficit / self.rate))


_buckets: dict[tuple[str, str], RateLimiter] = {}


def limiter_for(tenant_id: str, asset_id: str, rate_per_second: float) -> RateLimiter:
    key = (tenant_id, asset_id)
    limiter = _buckets.get(key)
    if limiter is None or abs(limiter.rate - max(0.1, float(rate_per_second))) > 1e-9:
        limiter = RateLimiter(rate_per_second)
        _buckets[key] = limiter
    return limiter


def reset() -> None:
    """Test helper: drop all buckets."""
    _buckets.clear()
