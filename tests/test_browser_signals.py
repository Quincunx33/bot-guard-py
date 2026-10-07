import io
import hashlib
import json
import re
import unittest

from bot_guard import BotGuard, BrowserSignalManager, ChallengeManager, VerifiedCrawlerAllowlist
from bot_guard.middleware.browser_signals import BrowserSignalASGI, BrowserSignalWSGI


def _solve(challenges, token, client_id):
    difficulty = challenges.browser_probe_difficulty(token, client_id)
    prefix = "0" * difficulty
    return next(str(n) for n in range(200000)
                if hashlib.sha256((token + str(n)).encode()).hexdigest().startswith(prefix))


class BrowserSignalTests(unittest.TestCase):
    def setUp(self):
        self.challenges = ChallengeManager("0123456789abcdef-browser-signal", challenge_ttl=60, attestation_ttl=120)
        self.manager = BrowserSignalManager(self.challenges)

    def test_signed_browser_report_drives_policy_but_verified_crawler_bypasses(self):
        client = "192.0.2.44"
        token = self.challenges.issue_browser_probe(client)
        accepted = self.manager.accept(client, {
            "token": token, "solution": _solve(self.challenges, token, client),
            "signals": {"webdriver": True, "automation_markers": [], "interaction_count": 2},
        })
        self.assertIsNotNone(accepted)
        self.assertTrue(accepted["automation_detected"])
        cookie = self.manager.cookie_name + "=" + accepted["attestation"]
        guard = BotGuard(browser_signal_provider=self.manager)
        result = guard.inspect({"User-Agent": "Mozilla/5.0 Chrome/154", "Cookie": cookie}, client)
        self.assertEqual(result.action, "BLOCK")
        self.assertIn("browser_signal:webdriver", result.matched_rules)

        trusted = VerifiedCrawlerAllowlist({"googlebot": ["192.0.2.0/24"]})
        guarded = BotGuard(browser_signal_provider=self.manager, trusted_crawler_verifier=trusted)
        crawler = guarded.inspect({"User-Agent": "Googlebot/2.1", "Cookie": cookie}, client)
        self.assertEqual(crawler.action, "ALLOW")
        self.assertIn("verified_crawler", crawler.matched_rules)

    def test_probe_token_is_client_bound_and_single_use(self):
        token = self.challenges.issue_browser_probe("client-a")
        payload = {"token": token, "solution": _solve(self.challenges, token, "client-a"),
                   "signals": {"webdriver": False, "automation_markers": [], "interaction_count": 3}}
        self.assertIsNone(self.manager.accept("client-b", payload))
        accepted = self.manager.accept("client-a", payload)
        self.assertIsNotNone(accepted)
        self.assertFalse(accepted["automation_detected"])
        self.assertIsNone(self.manager.accept("client-a", payload))

    def test_positive_signal_is_sticky_for_signed_cookie_lifetime(self):
        client = "192.0.2.77"
        positive = self.challenges.issue_browser_probe(client)
        first = self.manager.accept(client, {"token": positive, "solution": _solve(self.challenges, positive, client),
            "signals": {"webdriver": True, "automation_markers": [], "interaction_count": 0}})
        negative = self.challenges.issue_browser_probe(client)
        second = self.manager.accept(client, {"token": negative, "solution": _solve(self.challenges, negative, client),
            "signals": {"webdriver": False, "automation_markers": [], "interaction_count": 5}},
            current_cookie=first["attestation"])
        self.assertTrue(second["automation_detected"])
        cookie = self.manager.cookie_name + "=" + second["attestation"]
        self.assertTrue(self.manager.is_automated({"cookie": cookie}, client))

    def test_invalid_signal_types_are_rejected(self):
        token = self.challenges.issue_browser_probe("client")
        solution = _solve(self.challenges, token, "client")
        self.assertIsNone(self.manager.accept("client", {"token": token, "solution": solution, "signals": {"webdriver": "true"}}))
        self.assertIsNone(self.manager.accept("client", {"token": token, "solution": solution, "signals": {
            "webdriver": False, "automation_markers": ["not-allowlisted"], "interaction_count": 0,
        }}))
        self.assertIsNone(self.manager.accept("client", {"token": token, "solution": solution, "signals": {
            "webdriver": False, "automation_markers": [], "interaction_count": True,
        }}))

    def test_rendered_probe_contains_safe_webdriver_and_interaction_signals(self):
        script = self.manager.render_script("client", post_url="/__bot_guard/signal")
        self.assertIn("navigator.webdriver===true", script)
        self.assertIn("crypto.subtle", script)
        self.assertIn("interaction_count", script)
        self.assertIn("__bot_guard/signal", script)
        self.assertNotIn("0123456789abcdef-browser-signal", script)
        self.assertNotIn("{{", script)
        with self.assertRaises(ValueError):
            self.manager.render_script("client", post_url="//outside.invalid/signal")

    def test_wsgi_endpoint_issues_probe_then_sets_http_only_cookie(self):
        app = BrowserSignalWSGI(lambda environ, start: (start("200 OK", []), [b"app"])[1], self.manager)
        responses = []
        env = {"PATH_INFO": "/__bot_guard/probe.js", "REQUEST_METHOD": "GET", "REMOTE_ADDR": "192.0.2.10",
               "wsgi.url_scheme": "http", "HTTP_HOST": "test.local"}
        body = b"".join(app(env, lambda status, headers: responses.append((status, dict(headers)))))
        status, headers = responses[-1]
        self.assertEqual(status, "200 OK")
        self.assertEqual(headers["Content-Type"], "application/javascript; charset=utf-8")
        token = re.search(r"const token=\"([^\"]+)\"", body.decode()).group(1)
        payload = json.dumps({"token": token, "solution": _solve(self.challenges, token, "192.0.2.10"), "signals": {
            "webdriver": True, "automation_markers": ["webdriverScript"], "interaction_count": 0,
        }}).encode()
        env = {"PATH_INFO": "/__bot_guard/signal", "REQUEST_METHOD": "POST", "REMOTE_ADDR": "192.0.2.10",
               "wsgi.url_scheme": "https", "CONTENT_TYPE": "application/json", "CONTENT_LENGTH": str(len(payload)),
               "wsgi.input": io.BytesIO(payload)}
        responses.clear()
        self.assertEqual(list(app(env, lambda status, headers: responses.append((status, dict(headers))))), [])
        status, headers = responses[-1]
        self.assertEqual(status, "204 No Content")
        self.assertIn("HttpOnly", headers["Set-Cookie"])
        self.assertIn("Secure", headers["Set-Cookie"])
        self.assertIn("SameSite=Lax", headers["Set-Cookie"])
        self.assertIn("__bot_guard_signal=", headers["Set-Cookie"])

    def test_wsgi_endpoint_rejects_replay_and_oversize_body(self):
        app = BrowserSignalWSGI(lambda env, start: [], self.manager, max_body_bytes=512)
        token = self.challenges.issue_browser_probe("192.0.2.22")
        payload = json.dumps({"token": token, "solution": _solve(self.challenges, token, "192.0.2.22"),
                              "signals": {"webdriver": True, "automation_markers": [], "interaction_count": 0}}).encode()
        def post(body):
            result = []
            env = {"PATH_INFO": "/__bot_guard/signal", "REQUEST_METHOD": "POST", "REMOTE_ADDR": "192.0.2.22",
                   "CONTENT_TYPE": "application/json", "CONTENT_LENGTH": str(len(body)), "wsgi.input": io.BytesIO(body)}
            list(app(env, lambda status, headers: result.append(status)))
            return result[0]
        self.assertEqual(post(payload), "204 No Content")
        self.assertEqual(post(payload), "403 Forbidden")
        self.assertEqual(post(b" " * 600), "413 Payload Too Large")

    def test_asgi_probe_and_signal_routes(self):
        async def app(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"app"})
        middleware = BrowserSignalASGI(app, self.manager)

        async def invoke(path, method="GET", body=b""):
            messages = [{"type": "http.request", "body": body, "more_body": False}]
            sent = []
            async def receive(): return messages.pop(0)
            async def send(message): sent.append(message)
            headers = [(b"content-type", b"application/json")] if method == "POST" else []
            await middleware({"type": "http", "method": method, "path": path, "scheme": "http",
                              "client": ("192.0.2.30", 12345), "headers": headers}, receive, send)
            return sent
        import asyncio
        probe = asyncio.run(invoke("/__bot_guard/probe.js"))
        self.assertEqual(probe[0]["status"], 200)
        self.assertIn(b"application/javascript", dict(probe[0]["headers"])[b"content-type"])
        token = re.search(rb"const token=\"([^\"]+)\"", probe[1]["body"]).group(1).decode()
        body = json.dumps({"token": token, "solution": _solve(self.challenges, token, "192.0.2.30"),
                           "signals": {"webdriver": True, "automation_markers": [], "interaction_count": 1}}).encode()
        result = asyncio.run(invoke("/__bot_guard/signal", "POST", body))
        self.assertEqual(result[0]["status"], 204)
        self.assertIn(b"set-cookie", dict(result[0]["headers"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
