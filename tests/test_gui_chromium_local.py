"""Opt-in GUI-mode Chromium smoke test; all HTTP goes to 127.0.0.1.

Run with:
    BOT_GUARD_RUN_GUI_TESTS=1 xvfb-run -a python -m unittest tests.test_gui_chromium_local -v
"""
import json
import os
import threading
import time
import unittest
from wsgiref.simple_server import make_server

from bot_guard import BotGuard, BrowserSignalManager, ChallengeManager, DDoSProtector, VerifiedCrawlerAllowlist
from bot_guard.middleware.browser_signals import BrowserSignalWSGI
from bot_guard.middleware.generic import BotGuardWSGI, DDoSProtectionWSGI
from examples.ddos_protected_server import QuietRequestHandler, ThreadingWSGIServer

CHROMIUM = "/usr/bin/chromium"
try:
    from selenium import webdriver
except ImportError:
    webdriver = None

CRAWLER_UAS = (
    "Mozilla/5.0 (compatible; Googlebot/2.1)",
    "Mozilla/5.0 (compatible; bingbot/2.0)",
    "DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)",
    "DuckAssistBot/1.2; (+http://duckduckgo.com/duckassistbot.html)",
)


@unittest.skipUnless(
    os.environ.get("BOT_GUARD_RUN_GUI_TESTS") == "1" and webdriver is not None and os.path.isfile(CHROMIUM),
    "opt-in GUI test; use BOT_GUARD_RUN_GUI_TESTS=1 under xvfb-run with Selenium and Chromium",
)
class RealChromeGuiLocalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.challenge_manager = ChallengeManager("local-gui-browser-signal-secret-2026",
                                                 challenge_ttl=60, attestation_ttl=120)
        cls.signal_manager = BrowserSignalManager(cls.challenge_manager)
        cls.guard = BotGuard(browser_signal_provider=cls.signal_manager)
        cls.verifier = None
        cls.protector = DDoSProtector(per_client_rate=100, per_client_burst=200,
                                      global_rate=100, global_burst=200, max_concurrent=16)

        def app(environ, start_response):
            if environ.get("PATH_INFO") == "/":
                body = ("<!doctype html><meta charset='utf-8'><title>Local BotGuard test</title>"
                        "<h1>Local browser probe test</h1><script src='/__bot_guard/probe.js' defer></script>").encode()
                start_response("200 OK", [("Content-Type", "text/html; charset=utf-8"),
                                           ("Content-Length", str(len(body)))])
            else:
                body = json.dumps({"status": "ok"}).encode()
                start_response("200 OK", [("Content-Type", "application/json"),
                                           ("Content-Length", str(len(body)))])
            return [body]

        integrated = DDoSProtectionWSGI(BrowserSignalWSGI(app, cls.signal_manager), cls.protector)
        cls.app = BotGuardWSGI(integrated, cls.guard)
        cls.server = make_server("127.0.0.1", 0, cls.app, server_class=ThreadingWSGIServer,
                                 handler_class=QuietRequestHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.base_url = "http://127.0.0.1:{0}".format(cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=3)

    def test_real_gui_chrome_webdriver_probe_blocks_then_verified_crawlers_pass(self):
        options = webdriver.ChromeOptions()
        options.binary_location = CHROMIUM
        for flag in ("--no-sandbox", "--disable-dev-shm-usage", "--disable-background-networking", "--no-first-run"):
            options.add_argument(flag)
        # Deliberately do not use --headless: this launches full Chromium UI under Xvfb.
        driver = webdriver.Chrome(options=options)
        try:
            driver.set_window_size(1280, 800)
            driver.get(self.base_url + "/")
            chrome_ua = driver.execute_script("return navigator.userAgent")
            webdriver_flag = driver.execute_script("return navigator.webdriver")
            self.assertIn("Chrome/", chrome_ua)
            self.assertNotIn("HeadlessChrome", chrome_ua)
            self.assertTrue(webdriver_flag, "Selenium automation should be observable to page JavaScript")
            self.assertIn("Local browser probe test", driver.find_element("tag name", "body").text)
            driver.save_screenshot("/tmp/bot_guard_real_chrome_local.png")
            print("GUI Chromium UA:", chrome_ua)
            print("navigator.webdriver:", webdriver_flag)

            # The page's same-origin script posts a signed one-use signal. Wait
            # for its timer/fetch, then test that the signed HttpOnly cookie is enforced.
            time.sleep(1.4)
            driver.get(self.base_url + "/health")
            self.assertIn("Request blocked by bot-guard-py", driver.find_element("tag name", "body").text)

            # Test-only loopback range stands in for official ranges. Real sites
            # must load current CIDRs with examples/update_crawler_feeds.py.
            self.verifier = VerifiedCrawlerAllowlist({
                "googlebot": ["127.0.0.1/32"],
                "bingbot": ["127.0.0.1/32"],
                "duckduckbot": ["127.0.0.1/32"],
                "duckassistbot": ["127.0.0.1/32"],
            })
            self.guard.trusted_crawler_verifier = self.verifier
            self.protector.trusted_crawler_verifier = self.verifier
            for user_agent in CRAWLER_UAS:
                with self.subTest(user_agent=user_agent):
                    driver.execute_cdp_cmd("Network.setUserAgentOverride", {"userAgent": user_agent})
                    driver.get(self.base_url + "/health")
                    self.assertIn('"status": "ok"', driver.find_element("tag name", "body").text)
        finally:
            driver.quit()


if __name__ == "__main__":
    unittest.main(verbosity=2)
