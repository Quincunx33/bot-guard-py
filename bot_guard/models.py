"""Public data models and policy constants for bot-guard-py."""
from dataclasses import dataclass, field
from typing import List

HUMAN = "HUMAN"
CLI_TOOL = "CLI_TOOL"
HEADLESS_BROWSER = "HEADLESS_BROWSER"
SCRAPER = "SCRAPER"
SUSPICIOUS_HEADER = "SUSPICIOUS_HEADER"
ALLOW = "ALLOW"
MONITOR = "MONITOR"
CHALLENGE = "CHALLENGE"
RATE_LIMIT = "RATE_LIMIT"
BLOCK = "BLOCK"


@dataclass(frozen=True)
class BotResult:
    """Explainable inspection result with the recommended policy action."""
    is_bot: bool
    score: float
    reasons: List[str] = field(default_factory=list)
    bot_category: str = HUMAN
    action: str = ALLOW
    matched_rules: List[str] = field(default_factory=list)

    def explain(self) -> str:
        """Return a compact human-readable decision explanation."""
        rules = ", ".join(self.matched_rules) or "none"
        reasons = "; ".join(self.reasons) or "none"
        return "Decision: {0}\nScore: {1:.4f}\nCategory: {2}\nAction: {3}\nRules: {4}\nReasons: {5}".format(self.is_bot, self.score, self.bot_category, self.action, rules, reasons)
