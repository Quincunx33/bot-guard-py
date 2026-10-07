"""Command-line inspection utility: ``bot-guard inspect headers.json``."""
import argparse
import json
import sys
from .detector import BotGuard


def main(argv=None):
    parser = argparse.ArgumentParser(prog="bot-guard", description="Inspect HTTP headers with bot-guard-py")
    parser.add_argument("command", choices=("inspect", "explain"))
    parser.add_argument("file", nargs="?", default="-", help="JSON object file, or - for stdin")
    parser.add_argument("--threshold", type=float, default=.6)
    parser.add_argument("--mode", choices=("enforce", "shadow"), default="enforce")
    args = parser.parse_args(argv)
    try:
        raw = sys.stdin.read() if args.file == "-" else open(args.file, encoding="utf-8").read()
        headers = json.loads(raw)
        result = BotGuard(threshold=args.threshold, mode=args.mode).inspect(headers)
        if args.command == "explain": print(result.explain())
        else: print(json.dumps({"is_bot": result.is_bot, "score": result.score, "category": result.bot_category, "action": result.action, "reasons": result.reasons, "rules": result.matched_rules}, indent=2))
        return 1 if result.action == "BLOCK" else 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print("bot-guard: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
