"""Refresh cached official search-crawler IP feeds outside request handling.

Run periodically (for example, during deployment or a daily maintenance job):
    python examples/update_crawler_feeds.py --directory ./crawler-feeds

If any download or validation fails, existing cache files are left untouched.
"""
import argparse
import json
import os
import tempfile
from pathlib import Path
from urllib.request import Request, urlopen

from bot_guard import VerifiedCrawlerAllowlist

FEED_URLS = {
    "googlebot": "https://developers.google.com/static/crawling/ipranges/common-crawlers.json",
    "bingbot": "https://www.bing.com/toolbox/bingbot.json",
    "duckduckbot": "https://duckduckgo.com/duckduckbot.json",
    "duckassistbot": "https://duckduckgo.com/duckassistbot.json",
}
MAX_FEED_BYTES = 2 * 1024 * 1024


def update_feed_cache(directory, *, opener=None, timeout=15):
    """Download/validate all feeds, then atomically replace their cache files."""
    opener = opener or urlopen
    downloaded = {}
    for marker, url in FEED_URLS.items():
        request = Request(url, headers={"User-Agent": "bot-guard-py-crawler-feed-updater/0.6.3"})
        with opener(request, timeout=timeout) as response:
            payload = response.read(MAX_FEED_BYTES + 1)
        if len(payload) > MAX_FEED_BYTES:
            raise ValueError("{0} crawler feed exceeds size limit".format(marker))
        try:
            feed = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError("{0} crawler feed is not valid UTF-8 JSON".format(marker)) from exc
        # Reuse the exact CIDR parser used by request-time verification.
        VerifiedCrawlerAllowlist.from_json_feeds({marker: feed})
        downloaded[marker] = json.dumps(feed, sort_keys=True, indent=2) + "\n"

    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    written = []
    for marker, content in downloaded.items():
        destination = directory / (marker + ".json")
        temporary = None
        try:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=str(directory),
                                             prefix="." + marker + ".", delete=False) as stream:
                temporary = stream.name
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, 0o644)
            os.replace(temporary, destination)
            written.append(destination)
        finally:
            if temporary and os.path.exists(temporary):
                os.unlink(temporary)
    return written


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", default="crawler-feeds", help="Directory for cached feed JSON files")
    parser.add_argument("--timeout", type=float, default=15, help="Per-feed HTTPS timeout in seconds")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    try:
        paths = update_feed_cache(args.directory, timeout=args.timeout)
    except Exception as exc:
        parser.exit(1, "Feed refresh failed; existing cache was not intentionally replaced. Details: {0}\n".format(exc))
    for path in paths:
        print("Updated", path)


if __name__ == "__main__":
    main()
