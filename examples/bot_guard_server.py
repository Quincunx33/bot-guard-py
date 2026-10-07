"""Local integration server for adversarial bot-guard-py testing.

Run: python examples/bot_guard_server.py --host 0.0.0.0 --port 8765 --secret change-me
"""
import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlparse

from bot_guard import BehaviorTracker, BotGuard, ChallengeManager, InMemoryRateLimiter, Metrics


class GuardedHandler(BaseHTTPRequestHandler):
    guard = BotGuard(mode="enforce", threshold=0.6, challenge_at=0.2, rate_limit_at=0.5)
    metrics = Metrics()
    limiter = InMemoryRateLimiter(limit=20, window=1.0, max_keys=10000)
    behavior = BehaviorTracker(window=60, max_clients=10000)
    challenges = None

    def _client_ip(self):
        # Deliberately use the socket peer, not user-controlled forwarded headers.
        return self.client_address[0]

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/__bot_guard/challenge":
            token = self.challenges.issue(self._client_ip())
            return self._html(200, self.challenges.render(token, next_url=parse_qs(parsed.query).get("next", ["/"])[0]))
        if self._attested():
            return self._json(200, {"ok": True, "action": "ATTESTED"})
        self.behavior.observe(self._client_ip(), parsed.path, 0)
        result = self.guard.inspect(self.headers, client_ip=self._client_ip(), request_context={"path": parsed.path, "method": "GET"})
        self.metrics.observe(result)
        if result.action == "BLOCK": return self._json(403, {"error": "blocked", "category": result.bot_category, "score": result.score})
        if result.action == "RATE_LIMIT":
            self.limiter.allow(self._client_ip())
            return self._json(429, {"error": "rate_limited", "retry_after": 1})
        if result.action == "CHALLENGE":
            token = self.challenges.issue(self._client_ip())
            return self._html(403, self.challenges.render(token, next_url=parsed.path))
        return self._json(200, {"ok": True, "action": result.action, "score": result.score})

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != "/__bot_guard/verify":
            return self._json(404, {"error": "not_found"})
        length = min(int(self.headers.get("Content-Length", "0") or 0), 8192)
        data = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        token, solution = data.get("token", [""])[0], data.get("solution", [""])[0]
        if not self.challenges.verify(token, solution, self._client_ip()):
            return self._json(403, {"error": "invalid_challenge"})
        attestation = self.challenges.issue_attestation(self._client_ip())
        next_url = data.get("next", ["/"])[0]
        if not next_url.startswith("/") or next_url.startswith("//"):
            next_url = "/"
        self.send_response(303)
        self.send_header("Location", next_url if next_url.startswith("/") else "/")
        self.send_header("Set-Cookie", "bot_guard_attestation=" + attestation + "; Path=/; HttpOnly; SameSite=Lax")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _attested(self):
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        token = cookie.get("bot_guard_attestation")
        return bool(token and self.challenges.verify_attestation(token.value, self._client_ip()))

    def _json(self, status, payload):
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def _html(self, status, body):
        encoded = body.encode("utf-8")
        self.send_response(status); self.send_header("Content-Type", "text/html; charset=utf-8"); self.send_header("Content-Length", str(len(encoded))); self.end_headers(); self.wfile.write(encoded)

    def log_message(self, format, *args): return


def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--host", default="127.0.0.1"); parser.add_argument("--port", type=int, default=8765); parser.add_argument("--secret", default="local-development-secret-change-me")
    args = parser.parse_args()
    GuardedHandler.challenges = ChallengeManager(args.secret, difficulty=3)
    GuardedHandler.guard = BotGuard(mode="enforce", threshold=0.6, challenge_at=0.2, rate_limit_at=0.5, behavior_provider=GuardedHandler.behavior)
    server = ThreadingHTTPServer((args.host, args.port), GuardedHandler)
    print("bot-guard challenge server listening on http://{}:{}".format(args.host, args.port), flush=True)
    try: server.serve_forever()
    finally: server.server_close()


if __name__ == "__main__": main()
