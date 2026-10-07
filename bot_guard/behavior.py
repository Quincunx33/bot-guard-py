"""Dependency-free bounded behavioral history signals."""
from collections import defaultdict, deque
import threading
import time


class BehaviorTracker:
    """Track short-lived request history without storing raw headers."""
    def __init__(self, *, window=60.0, max_clients=10000, burst_threshold=30, path_threshold=12):
        if window <= 0 or not isinstance(max_clients, int) or max_clients < 1: raise ValueError("invalid behavior tracker limits")
        self.window, self.max_clients, self.burst_threshold, self.path_threshold = float(window), max_clients, burst_threshold, path_threshold
        self._events, self._lock = defaultdict(deque), threading.Lock()

    def _trim(self, key, now):
        events = self._events[key]
        while events and now - events[0][0] > self.window: events.popleft()

    def observe(self, client_id, path="/", status_code=0):
        key, now = str(client_id or "unknown"), time.monotonic()
        with self._lock:
            if key not in self._events and len(self._events) >= self.max_clients: self._events.pop(next(iter(self._events)))
            self._events[key].append((now, str(path)[:256], int(status_code)))
            self._trim(key, now)

    def score(self, headers, client_ip=None, context=None):
        key, now = str(client_ip or "unknown"), time.monotonic()
        with self._lock:
            if key not in self._events: return 0.0
            self._trim(key, now)
            events = self._events[key]
            count = len(events)
            unique_paths = len({event[1] for event in events})
            score = 0.0
            if count >= self.burst_threshold: score += 0.55
            if unique_paths >= self.path_threshold: score += 0.35
            if count and sum(event[2] == 404 or event[2] >= 500 for event in events) / count >= .5: score += .2
            return min(1.0, score)
