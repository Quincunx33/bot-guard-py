"""Optional real-browser tests. All navigation is restricted to loopback."""
import os
import threading
import unittest
from wsgiref.simple_server import make_server

from bot_guard import BotGuard, DDoSProtector, VerifiedCrawlerAllowlist
from bot_guard.middleware.generic import BotGuardWSGI
from examples.ddos_protected_server import QuietRequestHandler, ThreadingWSGIServer, create_app

CHROMIUM = "/usr/bin/chromium"
GOOGLEBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
BINGBOT = "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
DUCKDUCKBOT = "DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)"
DUCKASSISTBOT = "DuckAssistBot/1.2; (+http://duckduckgo.com/duckassistbot.html)"
CRAWLER_UAS = (GOOGLEBOT, BINGBOT, DUCKDUCKBOT, DUCKASSISTBOT)

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None

try:
    from selenium import webdriver
except ImportError:
    webdriver = None


@unittest.skipUnless(sync_playwright is not None and os.path.isfile(CHROMIUM),
                     "optional Playwright/system Chromium not installed")
class PlaywrightChromiumLocalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # The loopback range is a test fixture, never an operational crawler range.
        verifier = VerifiedCrawlerAllowlist({
            "googlebot": ["127.0.0.1/32"],
            "bingbot": ["127.0.0.1/32"],
            "duckduckbot": ["127.0.0.1/32"],
            "duckassistbot": ["127.0.0.1/32"],
        })
        guard = BotGuard(trusted_crawler_verifier=verifier)
        app = BotGuardWSGI(create_app(DDoSProtector(
            per_client_rate=100, per_client_burst=200,
            global_rate=100, global_burst=200, max_concurrent=16,
        )), guard)
        cls.server = make_server("127.0.0.1", 0, app, server_class=ThreadingWSGIServer,
                                 handler_class=QuietRequestHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.url = "http://127.0.0.1:{0}/health".format(cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=3)

    def test_playwright_headless_chromium_block_and_verified_crawlers_pass(self):
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                executable_path=CHROMIUM,
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-background-networking", "--no-first-run"],
            )
            try:
                page = browser.new_page()
                response = page.goto(self.url, wait_until="domcontentloaded", timeout=10000)
                self.assertIsNotNone(response)
                self.assertIn("HeadlessChrome", page.evaluate("navigator.userAgent"))
                self.assertEqual(response.status, 403)
                self.assertIn("Request blocked by bot-guard-py", page.locator("body").inner_text())

                for user_agent in CRAWLER_UAS:
                    with self.subTest(user_agent=user_agent):
                        context = browser.new_context(user_agent=user_agent)
                        crawler_page = context.new_page()
                        result = crawler_page.goto(self.url, wait_until="domcontentloaded", timeout=10000)
                        self.assertEqual(result.status, 200)
                        self.assertIn('"status": "ok"', crawler_page.locator("body").inner_text())
                        context.close()
            finally:
                browser.close()


@unittest.skipUnless(webdriver is not None and os.path.isfile(CHROMIUM),
                     "optional Selenium/system Chromium not installed")
class SeleniumChromiumLocalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        verifier = VerifiedCrawlerAllowlist({
            "googlebot": ["127.0.0.1/32"],
            "bingbot": ["127.0.0.1/32"],
            "duckduckbot": ["127.0.0.1/32"],
            "duckassistbot": ["127.0.0.1/32"],
        })
        guard = BotGuard(trusted_crawler_verifier=verifier)
        app = BotGuardWSGI(create_app(DDoSProtector(
            per_client_rate=100, per_client_burst=200,
            global_rate=100, global_burst=200, max_concurrent=16,
        )), guard)
        cls.server = make_server("127.0.0.1", 0, app, server_class=ThreadingWSGIServer,
                                 handler_class=QuietRequestHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.url = "http://127.0.0.1:{0}/health".format(cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=3)

    def test_selenium_headless_chromium_block_and_verified_crawlers_pass(self):
        options = webdriver.ChromeOptions()
        options.binary_location = CHROMIUM
        for flag in ("--headless=new", "--no-sandbox", "--disable-dev-shm-usage",
                     "--disable-background-networking", "--no-first-run"):
            options.add_argument(flag)
        driver = webdriver.Chrome(options=options)
        try:
            driver.get(self.url)
            self.assertIn("HeadlessChrome", driver.execute_script("return navigator.userAgent"))
            self.assertIn("Request blocked by bot-guard-py", driver.find_element("tag name", "body").text)

            for user_agent in CRAWLER_UAS:
                with self.subTest(user_agent=user_agent):
                    driver.execute_cdp_cmd("Network.setUserAgentOverride", {"userAgent": user_agent})
                    driver.get(self.url)
                    self.assertIn('"status": "ok"', driver.find_element("tag name", "body").text)
        finally:
            driver.quit()


if __name__ == "__main__":
    unittest.main(verbosity=2)
