from __future__ import annotations
import asyncio
import time
from dns_analyzer.utils.exceptions import RateLimitError

class RateLimiter:
    pass

class InMemoryRateLimiter(RateLimiter):
    def __init__(self, requests_per_minute: int, *, burst: int | None = None, name: str = "default"):
        self.name = name
        self.requests_per_minute = requests_per_minute
        self.capacity = float(burst or requests_per_minute)
        self._tokens = self.capacity
        self._refill_rate = requests_per_minute / 60.0
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()
    def _refill(self):
        now = time.monotonic()
        self._tokens = min(self.capacity, self._tokens + (now - self._last_refill) * self._refill_rate)
        self._last_refill = now
    async def acquire(self, tokens: int = 1):
        while True:
            async with self._lock:
                self._refill()
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                wait = (tokens - self._tokens) / self._refill_rate
            await asyncio.sleep(wait)
    async def try_acquire(self, tokens: int = 1) -> bool:
        async with self._lock:
            self._refill()
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False
    async def available_tokens(self) -> float:
        async with self._lock:
            self._refill()
            return round(self._tokens, 4)
    async def __aenter__(self): await self.acquire(); return self
    async def __aexit__(self, *a): pass

class StrictRateLimiter(InMemoryRateLimiter):
    async def acquire(self, tokens: int = 1):
        if not await self.try_acquire(tokens):
            raise RateLimitError(limit=self.requests_per_minute, window_seconds=60)

class RedisRateLimiter(InMemoryRateLimiter):
    pass

class RateLimiterRegistry:
    def __init__(self, limiters: dict):
        self._limiters = limiters
    @classmethod
    def from_settings(cls):
        from dns_analyzer.config.settings import get_settings
        s = get_settings()
        i = s.intel
        return cls({
            "virustotal": InMemoryRateLimiter(i.rate_limit_virustotal, name="virustotal"),
            "abuseipdb":  InMemoryRateLimiter(i.rate_limit_abuseipdb, name="abuseipdb"),
            "shodan":     InMemoryRateLimiter(i.rate_limit_shodan, name="shodan"),
            "ipinfo":     InMemoryRateLimiter(i.rate_limit_ipinfo, name="ipinfo"),
        })
    def get(self, name: str):
        if name not in self._limiters:
            self._limiters[name] = InMemoryRateLimiter(60, name=name)
        return self._limiters[name]
    def register(self, name: str, limiter): self._limiters[name] = limiter
    @property
    def names(self): return list(self._limiters.keys())
