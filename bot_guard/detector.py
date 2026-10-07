"""Core multi-layer bot detection and policy enforcement logic."""
import ipaddress
import math
from typing import Callable, List, Mapping, Optional, Sequence

from .models import ALLOW, BLOCK, CHALLENGE, CLI_TOOL, HEADLESS_BROWSER, HUMAN, MONITOR, RATE_LIMIT, SCRAPER, SUSPICIOUS_HEADER, BotResult
from .rules import BROWSER_UA_MARKERS, CLI_USER_AGENTS, HEADLESS_PATTERNS, PROXY_HEADERS, SCRAPER_PATTERNS

_DEFAULT_MAX_HEADERS = 128
_DEFAULT_MAX_VALUE_LENGTH = 4096


class BotGuard:
    """Fast, configurable, explainable header and policy detector.

    ``mode='enforce'`` produces progressive actions; ``mode='shadow'`` never
    blocks and reports ``MONITOR`` so thresholds can be tuned safely.
    """
    def __init__(self, threshold: float = 0.6, *, max_headers: int = _DEFAULT_MAX_HEADERS, max_value_length: int = _DEFAULT_MAX_VALUE_LENGTH,
                 mode: str = "enforce", allow_user_agents: Sequence[str] = (), deny_user_agents: Sequence[str] = (),
                 allow_ips: Sequence[str] = (), deny_ips: Sequence[str] = (), weights: Optional[Mapping[str, float]] = None,
                 challenge_at: float = 0.4, rate_limit_at: float = 0.5, block_at: Optional[float] = None,
                 reputation_provider=None, behavior_provider=None, event_sink: Optional[Callable[[dict], None]] = None,
                 metrics=None, trusted_crawler_verifier=None, browser_signal_provider=None) -> None:
        if isinstance(threshold, bool) or not math.isfinite(float(threshold)) or not 0.0 <= threshold <= 1.0:
            raise ValueError("threshold must be a number between 0.0 and 1.0")
        if mode not in ("enforce", "shadow"):
            raise ValueError("mode must be 'enforce' or 'shadow'")
        for name, value in (("max_headers", max_headers), ("max_value_length", max_value_length)):
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError(name + " must be a positive integer")
        if block_at is not None and not math.isfinite(float(block_at)):
            raise ValueError("block_at must be finite")
        if not all(math.isfinite(float(value)) for value in (challenge_at, rate_limit_at, block_at if block_at is not None else threshold)):
            raise ValueError("action thresholds must be finite")
        if not 0 <= challenge_at <= rate_limit_at <= (block_at if block_at is not None else threshold) <= 1:
            raise ValueError("action thresholds must satisfy 0 <= challenge_at <= rate_limit_at <= block_at <= 1")
        self.threshold, self.max_headers, self.max_value_length = float(threshold), max_headers, max_value_length
        self.mode, self.challenge_at, self.rate_limit_at, self.block_at = mode, challenge_at, rate_limit_at, block_at if block_at is not None else threshold
        self.allow_user_agents, self.deny_user_agents = self._patterns(allow_user_agents), self._patterns(deny_user_agents)
        self.allow_networks, self.deny_networks = self._networks(allow_ips), self._networks(deny_ips)
        # Weak/inconclusive hints remain deliberately low-weight to reduce false
        # positives: missing optional browser hints and proxy headers are common.
        defaults = {"cli_tool": .85, "headless": .75, "scraper": .65, "missing_browser_header": .08, "proxy_header": .05, "consistency": .2, "reputation": .3, "behavior": .4, "browser_automation": .9}
        self.weights = dict(defaults)
        if weights:
            self.weights.update({str(k): float(v) for k, v in weights.items()})
        if any(not math.isfinite(v) or v < 0 for v in self.weights.values()):
            raise ValueError("weights must be non-negative")
        if trusted_crawler_verifier is not None and not callable(trusted_crawler_verifier):
            raise TypeError("trusted_crawler_verifier must be callable")
        if browser_signal_provider is not None and not callable(getattr(browser_signal_provider, "is_automated", None)):
            raise TypeError("browser_signal_provider must provide is_automated(headers, client_ip)")
        self.reputation_provider, self.behavior_provider, self.event_sink, self.metrics = reputation_provider, behavior_provider, event_sink, metrics
        self.trusted_crawler_verifier = trusted_crawler_verifier
        self.browser_signal_provider = browser_signal_provider

    @staticmethod
    def _patterns(values):
        result = []
        for value in values:
            if not isinstance(value, str) or not value.strip():
                raise ValueError("allow/deny user-agent patterns must be non-empty strings")
            result.append(value.strip().lower())
        return tuple(result)

    @staticmethod
    def _networks(values):
        try:
            return tuple(ipaddress.ip_network(value, strict=False) for value in values)
        except (ValueError, TypeError) as exc:
            raise ValueError("allow_ips and deny_ips must contain valid IPs or CIDRs") from exc

    @staticmethod
    def _ip_in(ip, networks):
        if not ip:
            return False
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(address in network for network in networks)

    def inspect(self, headers: Optional[Mapping[object, object]], client_ip: Optional[str] = None, request_context=None) -> BotResult:
        if headers is None:
            headers = {}
        if isinstance(headers, Mapping):
            items = headers.items()
        else:
            items_method = getattr(headers, "items", None)
            if not callable(items_method):
                raise TypeError("headers must be a mapping or an object with items()")
            items = items_method()
        normalized = {}
        for index, (key, value) in enumerate(items):
            if index >= self.max_headers:
                break
            if value is not None and str(key).strip():
                normalized[str(key).strip().lower()] = str(value)[:self.max_value_length]
        ua = normalized.get("user-agent", "").lower()
        if self._ip_in(client_ip, self.deny_networks) or any(x in ua for x in self.deny_user_agents):
            return self._result(True, 1.0, ["Explicit denylist match"], ["denylist"], SUSPICIOUS_HEADER, client_ip)
        if self.trusted_crawler_verifier is not None:
            try:
                verified_crawler = bool(self.trusted_crawler_verifier(client_ip, ua))
            except Exception:
                verified_crawler = False
            if verified_crawler:
                return self._result(False, 0.0, ["Verified search crawler IP"], ["verified_crawler"], HUMAN, client_ip)
        if self._ip_in(client_ip, self.allow_networks) or self._matches_allowlist(ua, self.allow_user_agents):
            return self._result(False, 0.0, ["Explicit allowlist match"], ["allowlist"], HUMAN, client_ip)

        score, reasons, categories, rules = 0.0, [], [], []
        if self.browser_signal_provider is not None:
            try:
                automated = bool(self.browser_signal_provider.is_automated(normalized, client_ip))
            except Exception:
                automated = False
            if automated:
                score += self.weights["browser_automation"]
                reasons.append("Signed browser probe reported WebDriver automation")
                categories.append(HEADLESS_BROWSER)
                rules.append("browser_signal:webdriver")
        matched = self._first_match(ua, CLI_USER_AGENTS)
        if matched:
            score += self.weights["cli_tool"]; reasons.append("Suspicious User-Agent: " + matched); categories.append(CLI_TOOL); rules.append("cli_tool:" + matched)
        matched = self._first_match_in_headers(ua, normalized, HEADLESS_PATTERNS)
        if matched:
            score += self.weights["headless"]; reasons.append("Headless/automation signature: " + matched); categories.append(HEADLESS_BROWSER); rules.append("headless:" + matched)
        matched = self._first_match(ua, SCRAPER_PATTERNS)
        if matched:
            score += self.weights["scraper"]; reasons.append("Scraper signature: " + matched); categories.append(SCRAPER); rules.append("scraper:" + matched)
        is_browser = any(marker in ua for marker in BROWSER_UA_MARKERS)
        if is_browser and "chrome/" in ua:
            for header, label in (("sec-ch-ua", "Sec-CH-UA"), ("sec-fetch-dest", "Sec-Fetch-Dest"), ("accept-language", "Accept-Language")):
                if header not in normalized:
                    score += self.weights["missing_browser_header"]; reasons.append("Missing " + label + " for Chrome"); categories.append(HEADLESS_BROWSER); rules.append("missing:" + header)
            ch = normalized.get("sec-ch-ua", "").lower()
            if "firefox" in ch or "gecko" in ch:
                score += self.weights["consistency"]; reasons.append("Chrome User-Agent conflicts with Sec-CH-UA"); categories.append(SUSPICIOUS_HEADER); rules.append("header_consistency")
        elif is_browser and "firefox/" in ua and "accept-language" not in normalized:
            score += self.weights["missing_browser_header"]; reasons.append("Missing Accept-Language for Firefox"); categories.append(HEADLESS_BROWSER); rules.append("missing:accept-language")
        proxy_found = [label for key, label in PROXY_HEADERS.items() if normalized.get(key, "").strip()]
        if proxy_found:
            score += min(self.weights["proxy_header"] + .02 * (len(proxy_found) - 1), .12); reasons.append("Proxy/tunnel header: " + ", ".join(proxy_found)); categories.append(SUSPICIOUS_HEADER); rules.append("proxy_headers")
        if self.reputation_provider is not None:
            try:
                reputation = max(0.0, min(1.0, float(self.reputation_provider.score(normalized, client_ip))))
            except Exception:
                reputation = 0.0
            if reputation:
                score += reputation * self.weights["reputation"]; reasons.append("Reputation provider signal"); categories.append(SUSPICIOUS_HEADER); rules.append("reputation")
        if self.behavior_provider is not None:
            try:
                behavior = max(0.0, min(1.0, float(self.behavior_provider.score(normalized, client_ip, request_context))))
            except Exception:
                behavior = 0.0
            if behavior:
                score += behavior * self.weights["behavior"]; reasons.append("Behavior history signal"); categories.append(SUSPICIOUS_HEADER); rules.append("behavior_history")
        return self._result(True if score >= self.threshold else False, min(1.0, round(score, 4)), reasons, rules, self._category(categories, score, reasons), client_ip)

    def _result(self, is_bot, score, reasons, rules, category, client_ip):
        action = self._action(score, is_bot)
        result = BotResult(is_bot, score, reasons, category, action, rules)
        if self.metrics is not None:
            try:
                self.metrics.observe(result)
            except Exception:
                pass
        if self.event_sink is not None:
            try:
                self.event_sink({"score": result.score, "category": result.bot_category, "action": result.action, "rules": list(result.matched_rules), "client_ip": client_ip})
            except Exception:
                pass
        return result

    def _action(self, score, is_bot):
        if self.mode == "shadow": return MONITOR
        if score >= self.block_at and is_bot: return BLOCK
        if score >= self.rate_limit_at: return RATE_LIMIT
        if score >= self.challenge_at: return CHALLENGE
        return ALLOW

    def enforce(self, headers, client_ip=None, request_context=None):
        result = self.inspect(headers, client_ip, request_context)
        if result.action == BLOCK:
            from .exceptions import BotDetected
            raise BotDetected(result)
        return result

    @staticmethod
    def _matches_allowlist(ua, patterns):
        return any(ua == pattern or ua.startswith(pattern + "/") for pattern in patterns)

    @staticmethod
    def _first_match(value, patterns):
        for needle, label in patterns.items():
            if needle in value: return label
        return None

    @staticmethod
    def _first_match_in_headers(ua, headers, patterns):
        for needle, label in patterns.items():
            if needle in ua or any(needle in value.lower() for key, value in headers.items() if key != "user-agent"): return label
        return None

    @staticmethod
    def _category(categories, score, reasons):
        if not reasons: return HUMAN
        for category in (CLI_TOOL, HEADLESS_BROWSER, SCRAPER, SUSPICIOUS_HEADER):
            if category in categories: return category
        return SUSPICIOUS_HEADER if score else HUMAN
