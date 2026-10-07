"""Dependency-free HTTP bot detection and application-layer flood controls."""
from .detector import BotGuard
from .exceptions import BotDetected
from .models import BotResult, CLI_TOOL, HEADLESS_BROWSER, SCRAPER, SUSPICIOUS_HEADER, HUMAN
from .models import ALLOW, MONITOR, CHALLENGE, RATE_LIMIT, BLOCK
from .providers import ReputationProvider, InMemoryReputation
from .observability import Metrics
from .fingerprint import fingerprint
from .ratelimit import InMemoryRateLimiter
from .ddos import DDoSProtector, TokenBucketLimiter, VerifiedCrawlerAllowlist
from .challenge import ChallengeManager
from .behavior import BehaviorTracker
from .browser_signals import BrowserSignalManager

__all__ = ["BotGuard", "BotDetected", "BotResult", "ReputationProvider", "InMemoryReputation", "Metrics", "InMemoryRateLimiter", "DDoSProtector", "TokenBucketLimiter", "VerifiedCrawlerAllowlist", "ChallengeManager", "BehaviorTracker", "BrowserSignalManager", "fingerprint", "CLI_TOOL", "HEADLESS_BROWSER", "SCRAPER", "SUSPICIOUS_HEADER", "HUMAN", "ALLOW", "MONITOR", "CHALLENGE", "RATE_LIMIT", "BLOCK"]
__version__ = "0.7.0"
