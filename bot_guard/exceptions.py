"""Exceptions used by enforcement helpers."""
from .models import BotResult


class BotDetected(Exception):
    """Raised by :meth:`BotGuard.enforce` when a request should be blocked."""

    def __init__(self, result: BotResult) -> None:
        self.result = result
        super().__init__("Request blocked as bot: " + "; ".join(result.reasons))
