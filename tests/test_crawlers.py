import json
import unittest

from bot_guard import BotGuard, DDoSProtector, VerifiedCrawlerAllowlist
from bot_guard.middleware.generic import DDoSProtectionWSGI


GOOGLEBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
BINGBOT = "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
DUCKDUCKBOT = "DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)"
DUCKASSISTBOT = "DuckAssistBot/1.2; (+http://duckduckgo.com/duckassistbot.html)"


class CrawlerVerificationTests(unittest.TestCase):
    def setUp(self):
        # Documentation-only/reserved test ranges; never treated as real
        # vendor ranges. Production must load official, current CIDR lists.
        self.verified = VerifiedCrawlerAllowlist({
            "googlebot": ["192.0.2.0/24"],
            "bingbot": ["198.51.100.0/24"],
            "duckduckbot": ["203.0.113.0/24"],
            "duckassistbot": ["198.18.0.0/15"],
        })

    def test_user_agent_alone_does_not_exempt_fake_search_crawler(self):
        guard = BotGuard()
        for user_agent in (GOOGLEBOT, BINGBOT, DUCKDUCKBOT, DUCKASSISTBOT):
            with self.subTest(user_agent=user_agent):
                result = guard.inspect({"User-Agent": user_agent}, client_ip="192.0.2.250")
                self.assertTrue(result.is_bot)
                self.assertEqual(result.action, "BLOCK")

    def test_common_automation_signatures_are_blocked(self):
        guard = BotGuard()
        user_agents = [
            "curl/8.0", "python-requests/2.31", "Mozilla/5.0 HeadlessChrome/120",
            "Mozilla/5.0 Playwright", "ExampleSpider/1.0", GOOGLEBOT, BINGBOT,
            DUCKDUCKBOT, DUCKASSISTBOT,
        ]
        for user_agent in user_agents:
            with self.subTest(user_agent=user_agent):
                self.assertEqual(guard.inspect({"User-Agent": user_agent}, "203.0.113.8").action, "BLOCK")

    def test_all_verified_vendor_crawlers_are_not_bot_blocked(self):
        examples = [
            (GOOGLEBOT, "192.0.2.7"),
            (BINGBOT, "198.51.100.9"),
            (DUCKDUCKBOT, "203.0.113.11"),
            (DUCKASSISTBOT, "198.18.0.8"),
        ]
        guard = BotGuard(trusted_crawler_verifier=self.verified)
        for user_agent, ip in examples:
            with self.subTest(user_agent=user_agent):
                result = guard.inspect({"User-Agent": user_agent}, client_ip=ip)
                self.assertEqual((result.action, result.score), ("ALLOW", 0.0))
                self.assertIn("verified_crawler", result.matched_rules)

    def test_vendor_json_feed_prefixes_are_parsed(self):
        feed = json.dumps({"creationTime": "test", "prefixes": [
            {"ipv4Prefix": "192.0.2.0/24"}, {"ipv6Prefix": "2001:db8::/32"},
        ]})
        allowlist = VerifiedCrawlerAllowlist.from_json_feeds({"googlebot": feed})
        self.assertTrue(allowlist("192.0.2.12", GOOGLEBOT))
        self.assertTrue(allowlist("2001:db8::12", GOOGLEBOT))
        self.assertFalse(allowlist("198.51.100.2", GOOGLEBOT))
        with self.assertRaises(ValueError):
            VerifiedCrawlerAllowlist.from_json_feeds({"googlebot": "not-json"})

    def test_wrong_ip_and_explicit_denylist_do_not_get_crawler_exemption(self):
        fake = BotGuard(trusted_crawler_verifier=self.verified).inspect(
            {"User-Agent": DUCKDUCKBOT}, client_ip="192.0.2.250")
        denied = BotGuard(deny_ips=["192.0.2.7"], trusted_crawler_verifier=self.verified).inspect(
            {"User-Agent": GOOGLEBOT}, client_ip="192.0.2.7")
        self.assertEqual(fake.action, "BLOCK")
        self.assertEqual(denied.action, "BLOCK")

    def test_verified_crawler_skips_per_client_bucket_but_global_cap_remains(self):
        protector = DDoSProtector(per_client_rate=1, per_client_burst=1,
                                  global_rate=100, global_burst=100,
                                  trusted_crawler_verifier=self.verified)
        self.assertTrue(protector.check("203.0.113.7", DUCKDUCKBOT)[0])
        self.assertTrue(protector.check("203.0.113.7", DUCKDUCKBOT)[0])
        self.assertTrue(protector.check("192.0.2.7", GOOGLEBOT)[0])
        self.assertTrue(protector.check("198.51.100.9", BINGBOT)[0])
        self.assertTrue(protector.check("198.18.0.8", DUCKASSISTBOT)[0])
        self.assertTrue(protector.check("192.0.2.7", GOOGLEBOT)[0])
        self.assertTrue(protector.check("192.0.2.7", "spoofed DuckDuckBot/1.1 from non-DDG range")[0])
        allowed, _retry, reason = protector.check("192.0.2.7", "spoofed DuckDuckBot/1.1 from non-DDG range")
        self.assertFalse(allowed)
        self.assertEqual(reason, "client_rate")

    def test_wsgi_passes_user_agent_to_verifier(self):
        protector = DDoSProtector(per_client_rate=1, per_client_burst=1,
                                  global_rate=100, global_burst=100,
                                  trusted_crawler_verifier=self.verified)
        def app(environ, start_response):
            start_response("200 OK", [("Content-Length", "0")])
            return [b""]
        middleware = DDoSProtectionWSGI(app, protector)
        statuses = []
        for _ in range(2):
            response = middleware({"REMOTE_ADDR": "203.0.113.7", "HTTP_USER_AGENT": DUCKDUCKBOT},
                                  lambda status, headers: statuses.append(status))
            list(response)
        self.assertEqual(statuses, ["200 OK", "200 OK"])


if __name__ == "__main__":
    unittest.main()
