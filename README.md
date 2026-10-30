<div align="center">

# 🛡️ BOT GUARD

### A smarter first line of defense for your Python web app

**Spot suspicious requests. Slow down HTTP floods. Stay in control.**

<p>
  <a href="https://pypi.org/project/bot-guard-py/"><img src="https://img.shields.io/pypi/v/bot-guard-py?style=for-the-badge&color=7C3AED&label=PyPI" alt="PyPI version"></a>
  <a href="https://pypi.org/project/bot-guard-py/"><img src="https://img.shields.io/pypi/pyversions/bot-guard-py?style=for-the-badge&color=2563EB" alt="Supported Python versions"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-16A34A?style=for-the-badge" alt="MIT License"></a>
</p>

<p>
  <a href="https://github.com/Quincunx33/bot-guard-py/actions/workflows/ci.yml"><img src="https://github.com/Quincunx33/bot-guard-py/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/Core-No%20Dependencies-0F766E?style=flat-square" alt="No required runtime dependencies">
  <img src="https://img.shields.io/badge/ASGI%20%26%20WSGI-Supported-475569?style=flat-square" alt="ASGI and WSGI">
</p>

**[Get Started](#-get-started-in-30-seconds)** · **[Features](#-what-can-bot-guard-do)** · **[Examples](#-more-examples)** · **[Advanced Guide](docs/ADVANCED.md)** · **[Security](SECURITY.md)**

</div>

---

## 👋 Meet Bot Guard

Running a website or API? Not every visitor is a real person. Some requests come from scripts, scrapers, or automated clients; others arrive so quickly they overwhelm your app.

**Bot Guard** is a lightweight Python toolkit that helps your application **inspect requests, assign a risk score, and decide what to do next**.

You don't need to understand TLS, networking, or security engineering to try it. Start by *watching* traffic. Turn on blocking only when your rules make sense for your users.

> 🧭 **What it protects:** application-level HTTP traffic. Bot Guard does **not** replace a CDN, WAF, origin firewall, or network-level DDoS protection.

## ⚡ Get started in 30 seconds

**Requirements:** Python 3.9 or newer.

### 1. Install

```bash
python -m pip install bot-guard-py
```

### 2. Try your first check

Save this as `demo.py`:

```python
from bot_guard import BotGuard

# Safe starting mode: observe decisions without blocking requests.
guard = BotGuard(mode="shadow")

headers = {"User-Agent": "curl/8.0"}
result = guard.inspect(headers, client_ip="127.0.0.1")

print("Action:", result.action)
print("Risk score:", result.score)
print(result.explain())
```

Run it:

```bash
python demo.py
```

**That's it!** You've run your first bot inspection. Change the sample headers to explore how the scoring works.

**New here?** Keep `mode="shadow"` at first. This reports suspicious traffic without rejecting visitors.

## ✨ What can Bot Guard do?

| | Feature | In simple words |
|:--:|---|---|
| 🕵️ | **Bot detection** | Checks request headers for common automation and scraper signals |
| 📊 | **Explainable scores** | Shows a score, action, reasons, and matched rules |
| 🚦 | **Flexible decisions** | Allow, monitor, challenge, rate-limit, or block |
| ⏱️ | **Rate limiting** | Helps prevent clients from sending too many HTTP requests |
| 🧱 | **Concurrency protection** | Caps how many requests your app handles at once |
| 🧩 | **Framework adapters** | Works with FastAPI, Starlette, Flask, Django, and ASGI/WSGI |
| 🌐 | **Optional browser probe** | Can collect limited JavaScript automation signals on your own pages |
| 🔎 | **Crawler verification** | Supports verified search crawlers using official IP data |

*Signals are heuristics, not proof of identity. Check real traffic before enforcing aggressive rules.*

## 🧰 Plug it into your app

Using **FastAPI**? Add Bot Guard middleware to your existing application:

```bash
python -m pip install "bot-guard-py[fastapi]"
```

```python
from fastapi import FastAPI
from bot_guard import BotGuard
from bot_guard.middleware.fastapi import BotGuardMiddleware

app = FastAPI()
app.add_middleware(BotGuardMiddleware, guard=BotGuard(mode="shadow"))

@app.get("/")
def home():
    return {"message": "Hello from a Bot Guard-enabled app!"}
```

This begins in **monitor-only** mode. When you're ready to enforce policies, review the [Advanced Guide](docs/ADVANCED.md) for thresholds, challenge handling, limiter setup, and middleware ordering.

**Flask or Django?** Install `bot-guard-py[flask]` or `bot-guard-py[django]`, then follow the framework examples in the advanced guide.

## 🧪 More examples

<details>
<summary><b>🎲 Check any HTTP headers</b></summary>

<br>

```python
from bot_guard import BotGuard

guard = BotGuard(threshold=0.6)

result = guard.inspect({
    "User-Agent": "curl/8.0",
    "Accept": "*/*",
}, client_ip="127.0.0.1")

print(result.action)        # Suggested action
print(result.matched_rules) # Rules that matched
print(result.explain())     # Human-readable explanation
```

To actually reject a request, your application must apply the chosen policy (or use an appropriate middleware adapter).

</details>

<details>
<summary><b>🖥️ Try the command-line tool</b></summary>

<br>

Inspect a tiny JSON request example without writing a Python script:

```bash
echo '{"User-Agent":"curl/8.0"}' | bot-guard explain -
```

The CLI prints the decision and its reasons.

</details>

<details>
<summary><b>⏳ Add application-level rate limits</b></summary>

<br>

```python
from bot_guard import DDoSProtector
from bot_guard.middleware.fastapi import DDoSProtectionMiddleware

protector = DDoSProtector(
    per_client_rate=20,
    per_client_burst=60,
    global_rate=1000,
    global_burst=2000,
    max_concurrent=500,
)

# Add to an existing FastAPI app.
app.add_middleware(DDoSProtectionMiddleware, protector=protector)
```

These are example settings, **not universal safe limits**. Tune them to your app's capacity and real usage.

</details>

<details>
<summary><b>🧠 Explore browser signals and verified crawlers</b></summary>

<br>

Bot Guard also includes an **optional same-origin JavaScript probe** and utilities to verify known search-engine crawler IP ranges. Neither is needed for the basic detector.

For working configurations, lifecycle notes, and security limitations, read the [Advanced Guide](docs/ADVANCED.md).

</details>

## 🗺️ How it works

```text
Incoming HTTP request
         |
         v
  Inspect request signals
         |
         v
  Calculate a risk score
         |
         v
  Choose a policy action
         |
         +---- ALLOW / MONITOR
         +---- CHALLENGE
         +---- RATE_LIMIT
         +---- BLOCK
```

**Start by monitoring; enforce gradually.** False positives are possible, especially when visitors share IP addresses or have unusual browsers.

## ❓ Frequently asked questions

<details>
<summary><b>Do I need to know cybersecurity?</b></summary>

No. The quick-start example uses only Python basics. Advanced networking and framework configuration can come later.

</details>

<details>
<summary><b>Does Bot Guard stop every bot or DDoS attack?</b></summary>

No. Its signals are imperfect and it only handles requests **after they reach your application**. Keep upstream CDN, WAF, hosting, and firewall protections enabled.

</details>

<details>
<summary><b>Will it block real visitors?</b></summary>

It can if your thresholds are too strict. Start with shadow mode, review decisions, and tune policies on representative traffic before enabling blocking.

</details>

<details>
<summary><b>Does it require JavaScript or a database?</b></summary>

The core detector has no mandatory runtime dependencies and does not require JavaScript. The browser probe is optional. Built-in counters and limiters are process-local; distributed deployments may need shared storage or gateway limits.

</details>

<details>
<summary><b>Can I use it with Flask or Django?</b></summary>

Yes. Optional adapters support Flask, Django, and generic ASGI/WSGI applications. See the advanced guide for recommended setup.

</details>

## 📚 Documentation

| Guide | What you'll find |
|---|---|
| **[Advanced Technical Guide](docs/ADVANCED.md)** | Framework setup, challenges, rate limiting, crawler feeds, security notes, and detailed examples |
| **[Security Policy](SECURITY.md)** | Security guidance and reporting |
| **[Changelog](CHANGELOG.md)** | Release history |
| **[License](LICENSE)** | MIT License |

## 🤝 Development & contributing

Want to improve Bot Guard? Issues and thoughtful pull requests are welcome.

Run the repository's tests locally:

```bash
git clone https://github.com/Quincunx33/bot-guard-py.git
cd bot-guard-py
python -m pip install -e ".[test]"
python -m pytest -q
```

This project provides **application-layer protection and diagnostics**, not a guarantee that all malicious traffic will be detected or blocked. For production, configure trusted proxy handling, monitor false positives, and use upstream protections.

---

<div align="center">

### 🛡️ Protect thoughtfully. Start simply. Scale confidently.

**Bot Guard · Python 3.9+ · MIT License**

[PyPI](https://pypi.org/project/bot-guard-py/) · [Advanced Docs](docs/ADVANCED.md) · [Report a Security Issue](SECURITY.md)

<sub>Made for developers who want visibility and control without unnecessary complexity.</sub>

</div>
