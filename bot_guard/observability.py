"""Privacy-conscious observability helpers."""
from collections import Counter
from threading import Lock


class Metrics:
    """Thread-safe counters suitable for adapters to export to Prometheus/Otel."""
    def __init__(self) -> None:
        self._counts = Counter()
        self._lock = Lock()

    def observe(self, result) -> None:
        with self._lock:
            self._counts["requests_total"] += 1
            self._counts["actions_" + result.action.lower()] += 1
            self._counts["categories_" + result.bot_category.lower()] += 1

    def snapshot(self):
        with self._lock:
            return dict(self._counts)
