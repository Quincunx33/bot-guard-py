"""Small thread-safe fixed-window rate limiter with bounded key storage."""
import threading
import time


class InMemoryRateLimiter:
    def __init__(self, limit=60, window=60.0, max_keys=10000):
        if not isinstance(limit, int) or limit < 1 or window <= 0 or not isinstance(max_keys, int) or max_keys < 1:
            raise ValueError("limit/max_keys must be positive and window must be greater than zero")
        self.limit, self.window, self.max_keys = limit, float(window), max_keys
        self._items, self._lock = {}, threading.Lock()

    def _purge(self, now):
        expired = [key for key, (start, _) in self._items.items() if now - start >= self.window]
        for key in expired:
            self._items.pop(key, None)

    def allow(self, key):
        now, key = time.monotonic(), str(key)
        with self._lock:
            self._purge(now)
            if key not in self._items and len(self._items) >= self.max_keys:
                self._items.pop(next(iter(self._items)))
            start, count = self._items.get(key, (now, 0))
            count += 1
            self._items[key] = (start, count)
            return count <= self.limit

    def remaining(self, key):
        with self._lock:
            return max(0, self.limit - self._items.get(str(key), (0, 0))[1])
