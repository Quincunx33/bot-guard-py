"""Application-layer HTTP flood mitigation primitives.

These controls shed excess requests after they reach the application server.
They are not a substitute for network, CDN, or hosting-provider DDoS protection.
"""
import math
import threading
import time
from collections import OrderedDict
from collections.abc import Mapping
import ipaddress
import json


class TokenBucketLimiter:
    """Thread-safe, bounded token-bucket limiter.

    ``rate`` is the sustained refill rate in tokens/second and ``burst`` is the
    maximum short burst. Storage is bounded; least-recently-used client state
    is evicted when the key limit is reached. Pair per-client buckets with a
    global bucket so high-cardinality source floods are still capped.
    """
    def __init__(self, rate, burst, *, max_keys=50000):
        if isinstance(rate, bool) or not math.isfinite(float(rate)) or float(rate) <= 0:
            raise ValueError("rate must be a finite positive number")
        if isinstance(burst, bool) or not math.isfinite(float(burst)) or float(burst) < 1:
            raise ValueError("burst must be a finite number >= 1")
        if not isinstance(max_keys, int) or isinstance(max_keys, bool) or max_keys < 1:
            raise ValueError("max_keys must be a positive integer")
        self.rate, self.burst, self.max_keys = float(rate), float(burst), max_keys
        self._buckets = OrderedDict()
        self._lock = threading.Lock()

    def consume(self, key, amount=1.0):
        """Consume ``amount`` tokens; return ``(allowed, retry_after_seconds)``."""
        if isinstance(amount, bool) or not math.isfinite(float(amount)) or float(amount) <= 0:
            raise ValueError("amount must be a finite positive number")
        amount = float(amount)
        if amount > self.burst:
            raise ValueError("amount cannot exceed burst capacity")
        key, now = str(key), time.monotonic()
        with self._lock:
            bucket = self._buckets.pop(key, None)
            if bucket is None:
                tokens, updated = self.burst, now
            else:
                old_tokens, old_updated = bucket
                tokens = min(self.burst, old_tokens + max(0.0, now - old_updated) * self.rate)
                updated = now
            allowed = tokens >= amount
            if allowed:
                tokens -= amount
                retry_after = 0.0
            else:
                retry_after = (amount - tokens) / self.rate
            self._buckets[key] = (tokens, updated)
            if len(self._buckets) > self.max_keys:
                self._buckets.popitem(last=False)
            return allowed, retry_after


class VerifiedCrawlerAllowlist:
    """Verify named crawlers by matching their source IP to configured CIDRs.

    Example: ``VerifiedCrawlerAllowlist({"googlebot": google_cidrs,
    "bingbot": bing_cidrs})`` where CIDRs are maintained from the search
    engine's official published crawler ranges. A User-Agent match alone is
    never sufficient. Pass this callable to both ``BotGuard`` and
    ``DDoSProtector`` if those policies should recognize the same crawlers.
    """
    def __init__(self, networks_by_user_agent):
        if not isinstance(networks_by_user_agent, Mapping):
            raise TypeError("networks_by_user_agent must be a mapping of UA markers to CIDR lists")
        self.networks = {}
        for marker, networks in networks_by_user_agent.items():
            if not isinstance(marker, str) or not marker.strip():
                raise ValueError("crawler UA markers must be non-empty strings")
            if isinstance(networks, str):
                networks = [networks]
            try:
                parsed = tuple(ipaddress.ip_network(item, strict=False) for item in networks)
            except (ValueError, TypeError) as exc:
                raise ValueError("crawler ranges must be valid IP addresses or CIDRs") from exc
            if not parsed:
                raise ValueError("each crawler UA marker needs at least one IP range")
            self.networks[marker.strip().lower()] = parsed

    @classmethod
    def from_json_feeds(cls, feeds_by_user_agent):
        """Build an allowlist from parsed vendor JSON feed objects or JSON text.

        Expected feed shape is ``{"prefixes": [{"ipv4Prefix": "..."},
        {"ipv6Prefix": "..."}]}``, as published by Google, Bing, and
        DuckDuckGo. Fetch/cache feeds outside request handling and refresh them
        according to each vendor's guidance.
        """
        if not isinstance(feeds_by_user_agent, Mapping):
            raise TypeError("feeds_by_user_agent must map UA markers to JSON feed objects")
        networks = {}
        for marker, feed in feeds_by_user_agent.items():
            if isinstance(feed, (str, bytes)):
                try:
                    feed = json.loads(feed)
                except (ValueError, TypeError) as exc:
                    raise ValueError("crawler feed must be valid JSON") from exc
            if not isinstance(feed, Mapping) or not isinstance(feed.get("prefixes"), list):
                raise ValueError("crawler feed must contain a prefixes list")
            prefixes = []
            for item in feed["prefixes"]:
                if not isinstance(item, Mapping):
                    raise ValueError("crawler feed prefixes must be objects")
                prefixes.extend(item[key] for key in ("ipv4Prefix", "ipv6Prefix") if key in item)
            if not prefixes:
                raise ValueError("crawler feed contains no IPv4/IPv6 prefixes")
            networks[marker] = prefixes
        return cls(networks)

    def __call__(self, client_ip, user_agent):
        if not client_ip or not user_agent:
            return False
        try:
            address = ipaddress.ip_address(client_ip)
        except (ValueError, TypeError):
            return False
        ua = str(user_agent).lower()
        return any(marker in ua and any(address in network for network in ranges)
                   for marker, ranges in self.networks.items())


class DDoSProtector:
    """Apply per-client and global token-bucket budgets for HTTP requests.

    Defaults (20 requests/second per client, burst 60; 1,000 requests/second
    globally, burst 2,000; 500 concurrent app requests) are starting points,
    not universal capacity settings. Tune them to the application and hosting
    capacity. Limits are process-local unless custom shared limiters are given.
    """
    def __init__(self, *, per_client_rate=20.0, per_client_burst=60, global_rate=1000.0,
                 global_burst=2000, max_concurrent=500, max_clients=50000,
                 client_limiter=None, global_limiter=None, trusted_crawler_verifier=None):
        if not isinstance(max_concurrent, int) or isinstance(max_concurrent, bool) or max_concurrent < 1:
            raise ValueError("max_concurrent must be a positive integer")
        self.client_limiter = client_limiter if client_limiter is not None else TokenBucketLimiter(per_client_rate, per_client_burst, max_keys=max_clients)
        self.global_limiter = global_limiter if global_limiter is not None else TokenBucketLimiter(global_rate, global_burst, max_keys=1)
        if not callable(getattr(self.client_limiter, "consume", None)) or not callable(getattr(self.global_limiter, "consume", None)):
            raise TypeError("limiters must provide consume(key) -> (allowed, retry_after)")
        if trusted_crawler_verifier is not None and not callable(trusted_crawler_verifier):
            raise TypeError("trusted_crawler_verifier must be callable")
        self.trusted_crawler_verifier = trusted_crawler_verifier
        self.max_concurrent = max_concurrent
        self._active = 0
        self._active_lock = threading.Lock()

    def check(self, client_id, user_agent=None):
        """Return ``(allowed, retry_after, reason)`` for one incoming request."""
        client_key = str(client_id or "unknown")
        verified_crawler = False
        if self.trusted_crawler_verifier is not None:
            try:
                verified_crawler = bool(self.trusted_crawler_verifier(client_id, user_agent))
            except Exception:
                verified_crawler = False
        # Verified crawlers skip only the per-client bucket. The global budget
        # and concurrency cap still protect the application under aggregate load.
        if not verified_crawler:
            try:
                allowed, retry = self._consume(self.client_limiter, client_key)
            except Exception:
                return False, 1.0, "limiter_error"
            if not allowed:
                return False, retry, "client_rate"
        try:
            allowed, retry = self._consume(self.global_limiter, "global")
        except Exception:
            return False, 1.0, "limiter_error"
        if not allowed:
            return False, retry, "global_rate"
        return True, 0.0, None

    @staticmethod
    def _consume(limiter, key):
        result = limiter.consume(key)
        if not isinstance(result, (tuple, list)) or len(result) != 2:
            raise ValueError("limiter.consume must return (allowed, retry_after)")
        retry = float(result[1])
        if not math.isfinite(retry) or retry < 0:
            raise ValueError("limiter retry_after must be finite and non-negative")
        return bool(result[0]), retry

    def try_enter(self):
        """Reserve an application concurrency slot without waiting."""
        with self._active_lock:
            if self._active >= self.max_concurrent:
                return False
            self._active += 1
            return True

    def leave(self):
        """Release a previously acquired concurrency slot."""
        with self._active_lock:
            if self._active <= 0:
                raise RuntimeError("leave() called without a matching try_enter()")
            self._active -= 1

    @property
    def active_requests(self):
        with self._active_lock:
            return self._active
