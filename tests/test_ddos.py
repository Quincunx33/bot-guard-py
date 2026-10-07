import asyncio
import unittest
from unittest import mock

from bot_guard import DDoSProtector, TokenBucketLimiter
from bot_guard.middleware.generic import DDoSProtectionASGI, DDoSProtectionWSGI


class DDoSTests(unittest.TestCase):
    def test_token_bucket_limits_burst_and_refills(self):
        limiter = TokenBucketLimiter(rate=1, burst=1)
        with mock.patch("bot_guard.ddos.time.monotonic", side_effect=[10.0, 10.0, 11.0]):
            self.assertEqual(limiter.consume("client"), (True, 0.0))
            allowed, retry = limiter.consume("client")
            self.assertFalse(allowed)
            self.assertGreater(retry, 0.9)
            self.assertEqual(limiter.consume("client"), (True, 0.0))

    def test_global_bucket_caps_rotating_client_ids(self):
        protector = DDoSProtector(per_client_rate=100, per_client_burst=100,
                                  global_rate=1, global_burst=1)
        self.assertTrue(protector.check("ip-a")[0])
        allowed, retry, reason = protector.check("ip-b")
        self.assertFalse(allowed)
        self.assertEqual(reason, "global_rate")
        self.assertGreater(retry, 0)

    def test_broken_shared_limiter_fails_closed(self):
        class BrokenLimiter:
            def consume(self, key):
                raise RuntimeError("backend down")
        protector = DDoSProtector(client_limiter=BrokenLimiter())
        allowed, retry, reason = protector.check("ip-a")
        self.assertFalse(allowed)
        self.assertEqual(reason, "limiter_error")
        self.assertEqual(retry, 1.0)

    def test_client_buckets_are_isolated(self):
        protector = DDoSProtector(per_client_rate=1, per_client_burst=1,
                                  global_rate=100, global_burst=100)
        self.assertTrue(protector.check("ip-a")[0])
        self.assertFalse(protector.check("ip-a")[0])
        self.assertTrue(protector.check("ip-b")[0])

    def test_concurrency_slots_are_bounded_and_released(self):
        protector = DDoSProtector(max_concurrent=1)
        self.assertTrue(protector.try_enter())
        self.assertFalse(protector.try_enter())
        self.assertEqual(protector.active_requests, 1)
        protector.leave()
        self.assertEqual(protector.active_requests, 0)
        self.assertTrue(protector.try_enter())
        protector.leave()

    def test_wsgi_middleware_returns_429_then_allows_after_refill(self):
        calls = []
        def app(environ, start_response):
            calls.append(environ["REMOTE_ADDR"])
            start_response("200 OK", [("Content-Length", "2")])
            return [b"ok"]
        protector = DDoSProtector(per_client_rate=100, per_client_burst=100,
                                  global_rate=1, global_burst=1)
        middleware = DDoSProtectionWSGI(app, protector)
        responses = []
        first = middleware({"REMOTE_ADDR": "ip-a"}, lambda status, headers: responses.append((status, headers)))
        self.assertEqual(b"".join(first), b"ok")
        second = middleware({"REMOTE_ADDR": "ip-b"}, lambda status, headers: responses.append((status, headers)))
        self.assertEqual(responses[-1][0], "429 Too Many Requests")
        self.assertTrue(any(name == "Retry-After" for name, _ in responses[-1][1]))
        self.assertEqual(b"".join(second), b"Request rate limit exceeded.")
        self.assertEqual(calls, ["ip-a"])

    def test_wsgi_middleware_releases_concurrency_on_close(self):
        protector = DDoSProtector(max_concurrent=1)
        def app(environ, start_response):
            start_response("200 OK", [])
            return iter([b"stream"])
        middleware = DDoSProtectionWSGI(app, protector)
        first = middleware({"REMOTE_ADDR": "ip-a"}, lambda *args: None)
        self.assertEqual(protector.active_requests, 1)
        first.close()
        self.assertEqual(protector.active_requests, 0)

    def test_asgi_middleware_rejects_global_flood_with_429(self):
        calls = []
        async def app(scope, receive, send):
            calls.append(scope["client"][0])
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})
        protector = DDoSProtector(per_client_rate=100, per_client_burst=100,
                                  global_rate=1, global_burst=1)
        middleware = DDoSProtectionASGI(app, protector)
        async def request(ip):
            messages = []
            async def receive():
                return {"type": "http.request", "body": b"", "more_body": False}
            async def send(message):
                messages.append(message)
            await middleware({"type": "http", "client": (ip, 80), "headers": []}, receive, send)
            return messages
        async def run_both():
            return await request("ip-a"), await request("ip-b")
        first, second = asyncio.run(run_both())
        self.assertEqual(first[0]["status"], 200)
        self.assertEqual(second[0]["status"], 429)
        self.assertTrue(any(key == b"retry-after" for key, _ in second[0]["headers"]))
        self.assertEqual(calls, ["ip-a"])


if __name__ == "__main__":
    unittest.main()
