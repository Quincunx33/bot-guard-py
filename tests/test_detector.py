import unittest
from email.message import Message

from bot_guard import BotGuard, BotDetected, InMemoryReputation, Metrics, HUMAN, CLI_TOOL, HEADLESS_BROWSER, SCRAPER, SUSPICIOUS_HEADER, ALLOW, MONITOR, CHALLENGE, RATE_LIMIT, BLOCK


class BotGuardTests(unittest.TestCase):
    def setUp(self):
        self.guard = BotGuard()

    def test_normal_chrome_is_human(self):
        result = self.guard.inspect({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0 Safari/537.36", "Sec-CH-UA": '"Chromium";v="122"', "Sec-Fetch-Dest": "document", "Accept-Language": "en-US"})
        self.assertFalse(result.is_bot)
        self.assertEqual(result.bot_category, HUMAN)
        self.assertEqual(result.score, 0.0)

    def test_case_insensitive_cli_tool(self):
        result = self.guard.inspect({"uSeR-aGeNt": "python-requests/2.31.0"})
        self.assertTrue(result.is_bot)
        self.assertEqual(result.bot_category, CLI_TOOL)
        self.assertEqual(result.score, 0.85)

    def test_headless_and_missing_browser_headers(self):
        result = self.guard.inspect({"User-Agent": "Mozilla/5.0 HeadlessChrome/122.0"})
        self.assertTrue(result.is_bot)
        self.assertEqual(result.bot_category, HEADLESS_BROWSER)
        self.assertEqual(sum("Missing" in reason for reason in result.reasons), 3)

    def test_automation_signature_in_custom_header(self):
        result = self.guard.inspect({"User-Agent": "Mozilla/5.0", "X-Automation": "Playwright"})
        self.assertTrue(result.is_bot)
        self.assertEqual(result.bot_category, HEADLESS_BROWSER)

    def test_scraper(self):
        result = self.guard.inspect({"User-Agent": "ExampleSpider/1.0"})
        self.assertTrue(result.is_bot)
        self.assertEqual(result.bot_category, SCRAPER)

    def test_known_clients(self):
        for user_agent in ("curl/8.0", "Wget/1.21", "Go-http-client/1.1", "PostmanRuntime/7.0", "okhttp/4.0"):
            with self.subTest(user_agent=user_agent):
                self.assertEqual(self.guard.inspect({"User-Agent": user_agent}).bot_category, CLI_TOOL)

    def test_proxy_headers_are_explained_without_alone_blocking(self):
        result = self.guard.inspect({"User-Agent": "Mozilla/5.0", "Via": "1.1 proxy", "X-Forwarded-For": "10.0.0.1"})
        self.assertEqual(result.bot_category, SUSPICIOUS_HEADER)
        self.assertFalse(result.is_bot)
        self.assertIn("Proxy/tunnel header", result.reasons[0])

    def test_none_and_empty_values_are_safe(self):
        result = self.guard.inspect({"User-Agent": None, "Accept-Language": "", "": "ignored"})
        self.assertEqual(result.bot_category, HUMAN)
        self.assertEqual(result.score, 0.0)
        self.assertEqual(self.guard.inspect(None).score, 0.0)

    def test_email_message_header_container_is_supported(self):
        headers = Message()
        headers["User-Agent"] = "curl/8.0"
        self.assertEqual(self.guard.inspect(headers).action, BLOCK)

    def test_input_is_bounded(self):
        guard = BotGuard(max_headers=1, max_value_length=4)
        result = guard.inspect({"User-Agent": "python-requests/2.0", "Via": "proxy"})
        self.assertEqual(result.bot_category, HUMAN)
        self.assertEqual(guard.inspect({"User-Agent": "curl/8.0"}).bot_category, HUMAN)

    def test_type_and_threshold_validation(self):
        for value in (-0.1, 1.1, True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                BotGuard(value)
        with self.assertRaises(TypeError):
            self.guard.inspect([("User-Agent", "curl/8.0")])
        with self.assertRaises(ValueError):
            BotGuard(max_headers=0)
        with self.assertRaises(ValueError):
            BotGuard(max_value_length=0)

    def test_threshold_boundary_is_inclusive(self):
        self.assertTrue(BotGuard(threshold=0.85).inspect({"User-Agent": "curl/8.0"}).is_bot)
        self.assertFalse(BotGuard(threshold=0.851).inspect({"User-Agent": "curl/8.0"}).is_bot)

    def test_enforce_blocks_bots_and_returns_humans(self):
        with self.assertRaises(BotDetected) as caught:
            self.guard.enforce({"User-Agent": "curl/8.0"})
        self.assertEqual(caught.exception.result.bot_category, CLI_TOOL)
        self.assertEqual(self.guard.enforce({}).bot_category, HUMAN)

    def test_progressive_actions_and_shadow_mode(self):
        # Missing optional browser hints are weak evidence and should not
        # rate-limit an otherwise ordinary browser request by themselves.
        self.assertEqual(BotGuard().inspect({"User-Agent": "Mozilla/5.0 Chrome/122"}).action, ALLOW)
        self.assertEqual(BotGuard(mode="shadow").inspect({"User-Agent": "curl/8.0"}).action, MONITOR)
        self.assertEqual(BotGuard(challenge_at=.1, rate_limit_at=.2, block_at=.9).inspect({"User-Agent": "curl/8.0"}).action, RATE_LIMIT)

    def test_allow_and_deny_lists(self):
        allowed = BotGuard(allow_user_agents=["internal-agent"]).inspect({"User-Agent": "internal-agent/1.0"})
        spoofed = BotGuard(allow_user_agents=["internal-agent"]).inspect({"User-Agent": "internal-agent curl/8.0"})
        denied = BotGuard(deny_ips=["192.0.2.0/24"]).inspect({}, "192.0.2.7")
        self.assertEqual((allowed.action, allowed.bot_category), (ALLOW, HUMAN))
        self.assertEqual(spoofed.action, BLOCK)
        self.assertEqual(denied.action, BLOCK)

    def test_reputation_metrics_events_and_explain(self):
        reputation, metrics, events = InMemoryReputation(), Metrics(), []
        reputation.add("192.0.2.1", 1.0)
        result = BotGuard(reputation_provider=reputation, metrics=metrics, event_sink=events.append).inspect({}, "192.0.2.1")
        self.assertIn("Reputation provider signal", result.reasons)
        self.assertEqual(metrics.snapshot()["requests_total"], 1)
        self.assertEqual(events[0]["action"], result.action)
        self.assertIn("Score:", result.explain())

    def test_optional_failures_do_not_break_requests(self):
        class BrokenProvider:
            def score(self, headers, client_ip=None):
                raise RuntimeError("down")
        self.assertEqual(BotGuard(reputation_provider=BrokenProvider()).inspect({}).action, ALLOW)
        self.assertEqual(BotGuard(event_sink=lambda event: (_ for _ in ()).throw(RuntimeError("sink"))).inspect({}).action, ALLOW)

    def test_adversarial_configuration_is_rejected(self):
        with self.assertRaises(ValueError):
            BotGuard(weights={"cli_tool": float("nan")})
        with self.assertRaises(ValueError):
            BotGuard(allow_user_agents=[""])
        reputation = InMemoryReputation(max_items=2)
        for index in range(20):
            reputation.add(str(index))
        self.assertLessEqual(len(reputation._items), 2)
        limiter = __import__("bot_guard").InMemoryRateLimiter(max_keys=2)
        for index in range(20):
            limiter.allow(str(index))
        self.assertLessEqual(len(limiter._items), 2)


if __name__ == "__main__":
    unittest.main()
