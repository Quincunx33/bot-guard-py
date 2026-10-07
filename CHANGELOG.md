# Changelog

## 0.7.0 - 2026-10-08

- Added an opt-in signed JavaScript probe with a one-use SHA-256 proof-of-work nonce, `navigator.webdriver`/automation markers, and interaction telemetry.
- Added WSGI/ASGI probe endpoints and a signed, peer-IP-bound `HttpOnly` cookie; positive WebDriver signals feed BotGuard's risk score.
- Preserved verified search-crawler bypass before browser-signal scoring; added real GUI Selenium coverage showing WebDriver detection and crawler pass-through.
- Documented signal limitations, proxy identity alignment, and the first-request timing caveat.

## 0.6.3 - 2026-10-08

- Added a safe updater for current Google, Bing, DuckDuckBot, and DuckAssistBot IP feeds; validation completes before cached feeds are replaced.
- Added real local-only Chromium tests driven by Playwright and Selenium.
- Confirmed headless automation is blocked while CIDR-verified search crawler requests pass.

## 0.6.2 - 2026-10-08

- Added verified DuckDuckBot and DuckAssistBot handling alongside Googlebot and Bingbot.
- Added `VerifiedCrawlerAllowlist.from_json_feeds()` for vendor-published IPv4/IPv6 prefix feeds.
- Expanded bot and live loopback HTTP tests to cover Bing and both DuckDuckGo crawlers.
- Documented official crawler feed locations and refresh guidance.

## 0.6.1 - 2026-10-08

- Added CIDR-verified search crawler exemptions; User-Agent-only spoofing does not bypass bot checks.
- Verified crawlers skip per-client throttling while remaining subject to global and concurrency limits.
- Added spoofed Googlebot/Bingbot regression tests and documented official IP-range verification sources.
- Added a local WSGI demo server and real loopback HTTP flood/concurrency integration tests.

## 0.6.0 - 2026-10-08

- Added bounded token-bucket per-client and global HTTP rate limits plus a concurrent-request cap.
- Added ASGI/WSGI flood-protection middleware, a FastAPI alias, Flask WSGI installer, and Django middleware.
- Added configurable custom limiter hooks for shared/distributed stores.
- Documented that this mitigates application-layer HTTP floods only and does not replace upstream DDoS protection.
- Added automated tests for per-client/global limits, capacity shedding, retry headers, and WSGI slot cleanup.

## 0.5.1 - 2026-10-08

- Fixed middleware to pass the socket peer IP into detection and consistently handle challenge, rate-limit, and block actions.
- Added `on_action` callbacks to adapters while retaining Flask/FastAPI callback compatibility.
- Made verified proof-of-work challenges one-time per process and bounded the replay cache.
- Escaped challenge render inputs in JavaScript context to prevent inline-script breakout.
- Lowered weights for missing optional browser hints and proxy headers to reduce ordinary-traffic false positives.
- Added middleware/challenge regression tests and documented proxy/replay-store deployment requirements.

## 0.5.0 - 2026-10-08

- Added signed JavaScript proof-of-work challenges and short-lived browser attestations.
- Added bounded behavioral history scoring for bursts, path scans, and error-heavy clients.
- Added a behavior provider hook to `BotGuard`.

## 0.4.1 - 2026-10-08

- Fixed integration with stdlib and framework header containers exposing `items()` without implementing `Mapping`.
- Added a live ThreadingHTTPServer integration fixture with active 403/429 enforcement.
- Verified real concurrent request floods, oversized-header transport rejection, and server recovery.

## 0.4.0 - 2026-10-08

The engine now supports progressive actions (`ALLOW`, `MONITOR`, `CHALLENGE`, `RATE_LIMIT`, `BLOCK`), shadow mode, user-agent and IP/CIDR allowlists and denylists, configurable weights, browser-header consistency checks, a reputation-provider interface, short-lived in-memory reputation, structured event sinks, thread-safe metrics, explain output, a cross-platform CLI, generic ASGI/WSGI middleware, and an optional Django adapter.

It also includes privacy-aware header fingerprinting and a dependency-free local fixed-window rate limiter.

Red-team hardening added strict non-finite configuration rejection, exact/prefix-safe allowlist matching, fail-safe optional provider and telemetry hooks, bounded in-memory stores, and concurrency/middleware regression coverage.

## 0.3.0 - 2026-10-08

- Added direct `BotGuard.enforce()` and default middleware blocking.

## 0.2.0 - 2026-10-08

- Added bounded normalization, strict validation, expanded rules, typing metadata, CI, security guidance, and broader tests.

## 0.1.0 - 2026-10-08

- Initial release.
