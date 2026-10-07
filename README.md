# bot-guard-py

[![PyPI version](https://img.shields.io/pypi/v/bot-guard-py)](https://pypi.org/project/bot-guard-py/)
[![Python versions](https://img.shields.io/pypi/pyversions/bot-guard-py)](https://pypi.org/project/bot-guard-py/)
[![License](https://img.shields.io/pypi/l/bot-guard-py)](LICENSE)

**Lightweight bot detection and application-layer HTTP flood controls for Python.**

`bot-guard-py` adds configurable bot scoring, optional JavaScript browser signals, per-client/global rate limits, and concurrency shedding. It has **zero mandatory runtime dependencies** and works with ASGI and WSGI applications.

> **Scope:** This can reject HTTP requests after they reach your application. It does not stop volumetric/network DDoS or replace a CDN, WAF, hosting-provider protection, or origin firewall.

## Install

```bash
python -m pip install bot-guard-py
```

Optional framework extras are available:

```bash
python -m pip install 'bot-guard-py[fastapi]'
python -m pip install 'bot-guard-py[flask]'
python -m pip install 'bot-guard-py[django]'
```

The current release is `0.7.0`. Confirm the install with:

```bash
python -c "import bot_guard; print(bot_guard.__version__)"
```

## What it provides

| Feature | Purpose |
|---|---|
| Heuristic bot scoring | Identify common CLI clients, headless browsers, scrapers, and inconsistent browser headers |
| Browser-side probe | Optional signed JavaScript proof-of-work plus WebDriver/automation signals |
| Progressive policy | Allow, monitor, challenge, rate-limit, or block based on score and thresholds |
| Verified crawler handling | Match search-crawler User-Agent markers **and** current vendor IP ranges |
| HTTP flood controls | Bounded per-client/global token buckets and an in-flight request cap |
| Framework adapters | Generic ASGI/WSGI and FastAPI, Flask, and Django integrations |

## Quick start

Use the core directly when you want to apply the decision in your own request handler:

```python
from bot_guard import BotGuard

guard = BotGuard(threshold=0.6)
result = guard.inspect(request.headers, client_ip=client_ip)

if result.action == "BLOCK":
    return Response("Forbidden", status=403)
```

For gradual rollout, start in monitor-only mode:

```python
guard = BotGuard(mode="shadow")  # reports decisions; does not block
```

Use `result.explain()` for a readable explanation and `result.matched_rules` for stable rule IDs. Tune thresholds and weights for your own traffic; do not permanently ban someone based on one heuristic result.

## FastAPI / Starlette

The middleware order below makes BotGuard the outer policy layer, then rate/concurrency protection, then the browser-signal endpoints and your application:

```python
import os
from fastapi import FastAPI
from bot_guard import (
    BotGuard, BrowserSignalManager, ChallengeManager, DDoSProtector,
)
from bot_guard.middleware.fastapi import (
    BotGuardMiddleware, BrowserSignalMiddleware, DDoSProtectionMiddleware,
)

app = FastAPI()

# Keep this secret stable across restarts and private; use your deployment's
# secret manager/environment variables, never commit it to Git.
challenge = ChallengeManager(
    os.environ["BOT_GUARD_SECRET"], challenge_ttl=60, attestation_ttl=300,
)
signals = BrowserSignalManager(challenge)
guard = BotGuard(browser_signal_provider=signals)
protector = DDoSProtector(
    per_client_rate=20, per_client_burst=60,
    global_rate=1000, global_burst=2000,
    max_concurrent=500,
)

# Add inner-to-outer; the last added middleware runs first.
app.add_middleware(BrowserSignalMiddleware, signal_manager=signals)
app.add_middleware(DDoSProtectionMiddleware, protector=protector)
app.add_middleware(BotGuardMiddleware, guard=guard)
```

If you already have a FastAPI app, keep your existing routes and add the setup around it. BotGuard's default block response is `403`; rate limiting is `429`, and concurrency shedding is `503`.

## Optional JavaScript browser probe

The probe is **opt-in**. Add it to the shared HTML template for pages where you want browser-side signals:

```html
<script src="/__bot_guard/probe.js" defer></script>
```

The same-origin script solves a short SHA-256 nonce challenge and reports `navigator.webdriver`, a small set of automation globals, and an interaction count. The server validates the one-use proof and sets a signed, short-lived `HttpOnly; SameSite=Lax` cookie. A positive WebDriver signal adds risk and, with the default thresholds, is blocked on a later request.

A normal browser with JavaScript enabled is not blocked merely for having no interactions. Missing JavaScript is neutral. This is a heuristic—not a CAPTCHA or hardware-backed proof—and stealth automation can hide client-side signals. The first page request can finish before the probe reports, so protect sensitive actions with authentication, authorization, CSRF controls, and rate limits as appropriate.

For WSGI, wrap the app with `BrowserSignalWSGI` from `bot_guard.middleware.browser_signals` (or `bot_guard.middleware.BrowserSignalWSGI`) in the same order as the ASGI example.

## Protecting Flask / other WSGI apps

The generic WSGI adapters work with Flask or another WSGI application:

```python
from bot_guard import BotGuard, DDoSProtector
from bot_guard.middleware import BotGuardWSGI, DDoSProtectionWSGI, BrowserSignalWSGI

# `app` is your existing WSGI callable; set `signals` as shown above if using
# the optional JavaScript probe.
protector = DDoSProtector(per_client_rate=20, per_client_burst=60)
app = BotGuardWSGI(
    DDoSProtectionWSGI(BrowserSignalWSGI(app, signals), protector),
    BotGuard(browser_signal_provider=signals),
)
```

If you do not want the JavaScript probe, omit `BrowserSignalWSGI` and do not set `browser_signal_provider`. Flask also offers `init_bot_guard(app, guard)` and `init_ddos_protection(app, protector)` in `bot_guard.middleware.flask`; Django adapters are in `bot_guard.middleware.django`.

## Search-engine crawlers

Never exempt a crawler from its User-Agent text alone; it can be spoofed. Use current official IP feeds and give the same verifier to `BotGuard` and `DDoSProtector`:

```bash
python examples/update_crawler_feeds.py --directory ./crawler-feeds
```

This downloads and validates Google, Bing, DuckDuckBot, and DuckAssistBot ranges outside the request path. It writes `googlebot.json`, `bingbot.json`, `duckduckbot.json`, and `duckassistbot.json` only after validation. Load them at startup:

```python
import json
from pathlib import Path
from bot_guard import BotGuard, DDoSProtector, VerifiedCrawlerAllowlist

folder = Path("crawler-feeds")
read_feed = lambda name: json.loads((folder / name).read_text(encoding="utf-8"))
verified_crawlers = VerifiedCrawlerAllowlist.from_json_feeds({
    "googlebot": read_feed("googlebot.json"),
    "bingbot": read_feed("bingbot.json"),
    "duckduckbot": read_feed("duckduckbot.json"),
    "duckassistbot": read_feed("duckassistbot.json"),
})

guard = BotGuard(
    browser_signal_provider=signals,  # omit if not using the JS probe
    trusted_crawler_verifier=verified_crawlers,
)
protector = DDoSProtector(trusted_crawler_verifier=verified_crawlers)
```

Use these `guard` and `protector` objects in the framework setup above. A verified crawler skips heuristic bot blocking and the per-client rate bucket; it still consumes the global budget and concurrency capacity. Refresh the feeds periodically according to vendor guidance: [Google](https://developers.google.com/crawling/docs/crawlers-fetchers/verify-google-requests), [Bing](https://www.bing.com/webmasters/help/how-to-verify-bingbot-3905dc26), [DuckDuckBot](https://duckduckgo.com/duckduckbot.json), and [DuckAssistBot](https://duckduckgo.com/duckassistbot.json).

## Limits and deployment notes

- `DDoSProtector` starts at 20 requests/second per client (burst 60), 1,000/second globally (burst 2,000), and 500 concurrent application requests. **Tune these to measured capacity**; NAT users can share a client bucket.
- Built-in counters, token buckets, and challenge replay protection are process-local. Multi-worker or multi-host deployments need shared limiter/replay storage or enforcement at a gateway/CDN.
- Behind a reverse proxy, configure trusted-proxy handling before using IP-based rules. The default adapters use the socket peer and do not trust arbitrary `X-Forwarded-For` headers. The probe and BotGuard must resolve the same client IP.
- Keep CDN/WAF, hosting-provider DDoS controls, origin firewalling, and upstream limits enabled. This library only sheds application-layer HTTP load.

## Tests and local development

```bash
python -m pip install -e '.[test]'
python -m pytest -q
python -m compileall -q bot_guard examples
```

The suite includes unit tests, local HTTP flood tests, and optional Chromium/Selenium browser tests. Run the full GUI-mode test under Xvfb when Chromium, Selenium, and Xvfb are installed:

```bash
BOT_GUARD_RUN_GUI_TESTS=1 xvfb-run -a python -m pytest -q
```

## Build and publish

From the repository root, with a new version set in `pyproject.toml`:

```bash
python -m pip install --upgrade build twine
python -m build
python -m twine check dist/*
python -m twine upload dist/*
```

Use TestPyPI first if you want to rehearse the upload. Published files for a release version cannot be replaced; bump the version before publishing changes. Prefer a project-scoped PyPI token or Trusted Publishing, and never commit tokens or `.pypirc` files.

## License

MIT. See [LICENSE](LICENSE).
