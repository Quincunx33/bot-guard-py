# Security and deployment guidance

## Scope

`bot-guard-py` can actively block requests through `BotGuard.enforce()` or the optional middleware, but it remains heuristic enforcement based on request headers and opt-in client-reported browser signals. It is not a proof of identity, a CAPTCHA, an IP reputation database, or a replacement for authentication and authorization.

The `DDoSProtector` and its middleware provide **application-layer HTTP flood shedding only**. They run after traffic reaches the application process and cannot protect a saturated network link, load balancer, or origin from volumetric attacks. Keep provider/CDN/WAF protections and origin network controls enabled.

## Recommended production policy

- Use the built-in block as a first-line filter, then use rate limiting, authentication, and challenge flows for stronger controls.
- Do not permanently ban users from a single header result; keep the block reversible and observable.
- Run `mode="shadow"` first and review the structured event stream before enabling enforcement.
- Treat `client_ip` as trusted only when it is supplied by a configured, hardened reverse proxy.
- Middleware uses the socket peer address and does not parse forwarding headers. If deploying behind a proxy, configure the framework/server's trusted-proxy mechanism so `REMOTE_ADDR`/the ASGI peer is set safely before relying on IP rules.
- Challenge proofs are one-time only within a single `ChallengeManager` process. Use a shared replay store at the application layer for multi-worker or multi-host deployments.
- The optional browser probe uses a signed, peer-IP-bound one-use JavaScript proof and a signed `HttpOnly` cookie. `navigator.webdriver` and automation globals remain client-reported signals, not hardware-backed proof; stealth tooling can hide them. Missing telemetry is neutral, and the first page can load before the probe reports, so protect sensitive actions separately.
- Place the verified-crawler check before the browser-signal score. A verified crawler must be identified by current official CIDRs; never trust its User-Agent alone. Search crawlers need not execute the probe.
- Behind a reverse proxy, ensure the probe endpoint and `BotGuard` resolve the same trusted client address. The default uses the socket peer and does not trust forwarding headers.
- Keep reputation providers bounded, failure-safe, and free of raw header persistence.
- Monitor false positives and tune the threshold for the application and traffic mix.
- Keep reverse-proxy trust configuration separate from this library; forwarded headers can be user-controlled unless the proxy strips and rewrites them.
- Tune the global/per-client rate and concurrency limits to measured application capacity; overly low values cause self-inflicted denial of service, while overly high values may not protect an overloaded app.
- Built-in token buckets are process-local. Use shared custom limiter implementations or an upstream gateway for multi-worker/container/region consistency. Rotating source IPs can evade per-client limits, so the global budget and upstream controls are important.
- Never exempt Googlebot, Bingbot, DuckDuckBot, or DuckAssistBot by User-Agent text alone. Use `VerifiedCrawlerAllowlist` with current vendor-published CIDRs, or a strict reverse-DNS plus forward-confirmation verifier. A verified crawler still consumes global budget and a concurrency slot; refresh vendor feeds outside the request path.
- Avoid logging full header values if they may contain credentials or personal data.
- Keep dependencies for optional middleware in the host application and pin them according to your organization’s policy.

## Reporting issues

Please report reproducible security issues privately to the project maintainers rather than publishing exploit details first. Include the package version, Python version, operating system, minimal header input, and expected versus actual behavior.
