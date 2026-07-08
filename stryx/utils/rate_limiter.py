"""Async rate limiter for controlling request frequency."""

from __future__ import annotations

import asyncio
import time
from collections import deque


class RateLimiter:
    """Token-bucket style async rate limiter.

    Limits to `max_requests` requests per `window_seconds` period.
    """

    def __init__(self, max_requests: int = 20, window_seconds: float = 1.0):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._timestamps: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until a request slot is available."""
        async with self._lock:
            now = time.monotonic()
            # Remove expired timestamps
            while self._timestamps and self._timestamps[0] <= now - self.window_seconds:
                self._timestamps.popleft()

            if len(self._timestamps) >= self.max_requests:
                # Wait until the oldest request expires
                wait_time = self._timestamps[0] + self.window_seconds - now
                if wait_time > 0:
                    await asyncio.sleep(wait_time)
                self._timestamps.popleft()

            self._timestamps.append(time.monotonic())
