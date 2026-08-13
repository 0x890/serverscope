"""Async retry with exponential backoff and a token-bucket rate limiter."""
from __future__ import annotations

import asyncio
import logging
import random
import time
from collections.abc import Awaitable, Callable
from typing import TypeVar

T = TypeVar("T")
log = logging.getLogger(__name__)


async def retry_async(
    fn: Callable[[], Awaitable[T]],
    *,
    retries: int = 3,
    backoff_seconds: float = 2.0,
    timeout_seconds: float | None = None,
    what: str = "operation",
) -> T:
    last_exc: BaseException | None = None
    for attempt in range(1, retries + 1):
        try:
            if timeout_seconds:
                return await asyncio.wait_for(fn(), timeout=timeout_seconds)
            return await fn()
        except asyncio.CancelledError:
            raise
        except BaseException as exc:  # noqa: BLE001 - deliberate catch-all for retry
            last_exc = exc
            if attempt == retries:
                break
            delay = backoff_seconds * (2 ** (attempt - 1)) * (0.5 + random.random())
            log.warning("%s failed (attempt %d/%d): %s — retrying in %.1fs",
                        what, attempt, retries, exc, delay)
            await asyncio.sleep(delay)
    assert last_exc is not None
    raise last_exc


class RateLimiter:
    """Token bucket: allows `rate` acquisitions per second."""

    def __init__(self, rate: float, burst: int | None = None) -> None:
        self._rate = max(rate, 0.001)
        self._capacity = float(burst if burst is not None else max(1, int(rate)))
        self._tokens = self._capacity
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                self._tokens = min(self._capacity, self._tokens + (now - self._updated) * self._rate)
                self._updated = now
                if self._tokens >= 1:
                    self._tokens -= 1
                    return
                await asyncio.sleep((1 - self._tokens) / self._rate)
