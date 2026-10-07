"""Real HTTP integration and bounded load tests against loopback only."""
import http.client
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from wsgiref.simple_server import make_server

from bot_guard import BotGuard, DDoSProtector, VerifiedCrawlerAllowlist
from bot_guard.middleware.generic import BotGuardWSGI, DDoSProtectionWSGI
from examples.ddos_protected_server import QuietRequestHandler, ThreadingWSGIServer, create_app


def _request(port, path="/health", user_agent=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        headers = {"Connection": "close"}
        if user_agent:
            headers["User-Agent"] = user_agent
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        headers = {key.lower(): value for key, value in response.getheaders()}
        response.read()
        return response.status, headers
    finally:
        connection.close()


class HTTPFloodIntegrationTests(unittest.TestCase):
    def _server(self, app):
        server = make_server("127.0.0.1", 0, app, server_class=ThreadingWSGIServer,
                             handler_class=QuietRequestHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread

    def test_normal_http_requests_reach_application(self):
        protector = DDoSProtector(per_client_rate=100, per_client_burst=100,
                                  global_rate=100, global_burst=100, max_concurrent=32)
        server, thread = self._server(create_app(protector))
        try:
            statuses = [_request(server.server_port)[0] for _ in range(30)]
            self.assertEqual(statuses, [200] * 30)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    def test_real_http_automation_is_blocked_and_verified_search_crawlers_pass(self):
        # 127.0.0.1 is a deterministic test-only CIDR; production must use
        # current Google/Bing/DuckDuckGo vendor-published ranges.
        crawler_check = VerifiedCrawlerAllowlist({
            "googlebot": ["127.0.0.1/32"],
            "bingbot": ["127.0.0.1/32"],
            "duckduckbot": ["127.0.0.1/32"],
            "duckassistbot": ["127.0.0.1/32"],
        })
        guard = BotGuard(trusted_crawler_verifier=crawler_check)
        protector = DDoSProtector(per_client_rate=100, per_client_burst=100,
                                  global_rate=100, global_burst=100, max_concurrent=16)
        server, thread = self._server(BotGuardWSGI(create_app(protector), guard))
        try:
            self.assertEqual(_request(server.server_port, user_agent="Mozilla/5.0 HeadlessChrome/120")[0], 403)
            self.assertEqual(_request(server.server_port, user_agent="curl/8.0")[0], 403)
            crawler_user_agents = [
                "Mozilla/5.0 (compatible; Googlebot/2.1)",
                "Mozilla/5.0 (compatible; bingbot/2.0)",
                "DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)",
                "DuckAssistBot/1.2; (+http://duckduckgo.com/duckassistbot.html)",
            ]
            for user_agent in crawler_user_agents:
                with self.subTest(user_agent=user_agent):
                    self.assertEqual(_request(server.server_port, user_agent=user_agent)[0], 200)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    def test_concurrent_requests_are_capped_before_app_work(self):
        active, peak = 0, 0
        state_lock = threading.Lock()
        both_entered = threading.Event()
        release = threading.Event()

        def app(environ, start_response):
            nonlocal active, peak
            with state_lock:
                active += 1
                peak = max(peak, active)
                if active >= 2:
                    both_entered.set()
            release.wait(timeout=3)
            with state_lock:
                active -= 1
            body = b"ok"
            start_response("200 OK", [("Content-Length", str(len(body)))])
            return [body]

        protector = DDoSProtector(per_client_rate=100, per_client_burst=100,
                                  global_rate=100, global_burst=100, max_concurrent=2)
        server, thread = self._server(DDoSProtectionWSGI(app, protector))
        try:
            with ThreadPoolExecutor(max_workers=3) as pool:
                first = pool.submit(_request, server.server_port)
                second = pool.submit(_request, server.server_port)
                self.assertTrue(both_entered.wait(timeout=2), "two requests should enter the app")
                third = _request(server.server_port)
                self.assertEqual(third[0], 503)
                self.assertEqual(third[1].get("retry-after"), "1")
                release.set()
                self.assertEqual(first.result(timeout=3)[0], 200)
                self.assertEqual(second.result(timeout=3)[0], 200)
            self.assertEqual(peak, 2)
            self.assertEqual(protector.active_requests, 0)
        finally:
            release.set()
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    def test_1000_request_local_http_flood_is_shed_by_rate_limiter(self):
        protector = DDoSProtector(per_client_rate=0.001, per_client_burst=12,
                                  global_rate=1000, global_burst=1000, max_concurrent=32)
        server, thread = self._server(create_app(protector))
        try:
            # All clients originate from this loopback-only test process. No
            # external host/service receives any test traffic.
            with ThreadPoolExecutor(max_workers=32) as pool:
                results = list(pool.map(lambda _: _request(server.server_port), range(1000)))
            status_counts = {}
            for status, _headers in results:
                status_counts[status] = status_counts.get(status, 0) + 1
            self.assertLessEqual(status_counts.get(200, 0), 12)
            self.assertGreaterEqual(status_counts.get(429, 0), 988)
            self.assertTrue(all(int(headers.get("retry-after", "0")) >= 1 for status, headers in results if status == 429))
            self.assertEqual(protector.active_requests, 0)
            print("loopback flood report:", status_counts)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
