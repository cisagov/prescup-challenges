from __future__ import annotations
import asyncio, time
from dataclasses import dataclass

@dataclass
class Bucket:
    tokens: float
    last: float

class TokenBucketLimiter:
    def __init__(self, rate_per_min: int, burst: int):
        self.rate_per_sec = rate_per_min / 60.0
        self.burst = float(burst)
        self._buckets: dict[str, Bucket] = {}
        self._lock = asyncio.Lock()

    async def allow(self, key: str) -> bool:
        now = time.time()
        async with self._lock:
            b = self._buckets.get(key)
            if b is None:
                b = Bucket(tokens=self.burst, last=now)
                self._buckets[key] = b
            dt = now - b.last
            b.last = now
            b.tokens = min(self.burst, b.tokens + dt * self.rate_per_sec)
            if b.tokens >= 1.0:
                b.tokens -= 1.0
                return True
            return False
