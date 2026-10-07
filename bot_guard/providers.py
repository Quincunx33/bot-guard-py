"""Optional provider interfaces and bounded process-local reputation."""
import threading
import time
from typing import Mapping, Optional


class ReputationProvider:
    def score(self, headers: Mapping[str, str], client_ip: Optional[str] = None) -> float:
        return 0.0


class InMemoryReputation(ReputationProvider):
    """Thread-safe, TTL-bound reputation store with a configurable key cap."""
    def __init__(self, ttl: float = 300.0, max_items: int = 10000) -> None:
        if ttl <= 0 or not isinstance(max_items, int) or max_items < 1:
            raise ValueError("ttl must be positive and max_items must be a positive integer")
        self.ttl, self.max_items = float(ttl), max_items
        self._items, self._lock = {}, threading.Lock()

    def _purge(self, now):
        expired = [key for key, (_, expires) in self._items.items() if expires <= now]
        for key in expired:
            self._items.pop(key, None)

    def add(self, key: str, points: float = 0.1) -> None:
        now = time.monotonic()
        with self._lock:
            self._purge(now)
            if str(key) not in self._items and len(self._items) >= self.max_items:
                self._items.pop(next(iter(self._items)))
            score, _ = self._items.get(str(key), (0.0, 0.0))
            self._items[str(key)] = (min(1.0, score + float(points)), now + self.ttl)

    def score(self, headers: Mapping[str, str], client_ip: Optional[str] = None) -> float:
        key, now = str(client_ip or headers.get("user-agent", "")), time.monotonic()
        with self._lock:
            score, expires = self._items.get(key, (0.0, 0.0))
            if expires <= now:
                self._items.pop(key, None)
                return 0.0
            return score
