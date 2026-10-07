import json
import tempfile
import unittest
from pathlib import Path

from examples.update_crawler_feeds import FEED_URLS, update_feed_cache


class FakeResponse:
    def __init__(self, body):
        self.body = body
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def read(self, limit=-1):
        return self.body[:limit] if limit >= 0 else self.body


class FeedUpdaterTests(unittest.TestCase):
    def _opener(self, payloads):
        def opener(request, timeout):
            self.assertGreater(timeout, 0)
            return FakeResponse(payloads[request.full_url])
        return opener

    def test_updates_all_cached_feeds_after_validating_the_set(self):
        payloads = {
            url: json.dumps({"creationTime": "test", "prefixes": [{"ipv4Prefix": "192.0.2.0/24"}]}).encode()
            for url in FEED_URLS.values()
        }
        with tempfile.TemporaryDirectory() as directory:
            paths = update_feed_cache(directory, opener=self._opener(payloads))
            self.assertEqual({path.name for path in paths}, {name + ".json" for name in FEED_URLS})
            for path in paths:
                data = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(data["prefixes"][0]["ipv4Prefix"], "192.0.2.0/24")

    def test_invalid_feed_leaves_existing_cache_untouched(self):
        payloads = {
            url: json.dumps({"prefixes": [{"ipv4Prefix": "192.0.2.0/24"}]}).encode()
            for url in FEED_URLS.values()
        }
        payloads[FEED_URLS["duckassistbot"]] = b"not-json"
        with tempfile.TemporaryDirectory() as directory:
            cached = Path(directory) / "googlebot.json"
            cached.write_text("old trusted cache", encoding="utf-8")
            with self.assertRaises(ValueError):
                update_feed_cache(directory, opener=self._opener(payloads))
            self.assertEqual(cached.read_text(encoding="utf-8"), "old trusted cache")
            self.assertEqual(list(Path(directory).iterdir()), [cached])


if __name__ == "__main__":
    unittest.main(verbosity=2)
