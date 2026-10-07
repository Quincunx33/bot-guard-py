"""Small, intentionally auditable rule tables used by :mod:`bot_guard.detector`."""

CLI_USER_AGENTS = {
    "curl/": "cURL", "wget/": "Wget", "python-requests": "python-requests", "python/": "Python",
    "httpx": "httpx", "scrapy": "Scrapy", "go-http-client": "Go HTTP client", "aiohttp": "aiohttp",
    "postmanruntime": "Postman", "java/": "Java HTTP client", "libwww-perl": "libwww-perl",
    "okhttp": "OkHttp", "powershell": "PowerShell", "mechanize": "mechanize",
}
HEADLESS_PATTERNS = {
    "headlesschrome": "Headless Chrome", "headless firefox": "Headless Firefox", "phantomjs": "PhantomJS",
    "puppeteer": "Puppeteer", "playwright": "Playwright", "selenium": "Selenium", "webdriver": "WebDriver",
}
SCRAPER_PATTERNS = {
    "bot/": "bot", "bot ": "bot", "crawler": "crawler", "spider": "spider", "scraper": "scraper", "fetcher": "fetcher",
    "google web preview": "Google Web Preview", "facebookexternalhit": "Facebook crawler",
}
PROXY_HEADERS = {
    "via": "Via", "x-forwarded-for": "X-Forwarded-For", "forwarded": "Forwarded",
    "x-proxy-id": "X-Proxy-ID", "x-real-ip": "X-Real-IP", "cf-worker": "CF-Worker", "cdn-loop": "Cdn-Loop",
}
BROWSER_UA_MARKERS = ("mozilla/5.0", "chrome/", "firefox/", "safari/", "edg/")
