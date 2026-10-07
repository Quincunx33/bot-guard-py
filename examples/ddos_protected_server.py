"""Local demo HTTP server with application-layer flood controls.

This is a test/demo server, not a public DDoS edge. It binds to loopback by
 default so it cannot accidentally expose itself on the public interface.
"""
import argparse
import json
from wsgiref.simple_server import WSGIServer, WSGIRequestHandler, make_server
from socketserver import ThreadingMixIn

from bot_guard import DDoSProtector
from bot_guard.middleware.generic import DDoSProtectionWSGI


class ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True
    allow_reuse_address = True


class QuietRequestHandler(WSGIRequestHandler):
    def log_message(self, format, *args):
        pass


def create_app(protector=None):
    """Create a minimal JSON WSGI app protected by the configured limiter."""
    def app(environ, start_response):
        if environ.get("PATH_INFO") == "/health":
            status, payload = "200 OK", {"status": "ok"}
        elif environ.get("PATH_INFO") == "/":
            status, payload = "200 OK", {"message": "local DDoS-protected demo", "protection": "application-layer HTTP limits"}
        else:
            status, payload = "404 Not Found", {"error": "not found"}
        body = json.dumps(payload).encode("utf-8")
        start_response(status, [("Content-Type", "application/json"), ("Content-Length", str(len(body)))])
        return [body]
    return DDoSProtectionWSGI(app, protector or DDoSProtector())


def main():
    parser = argparse.ArgumentParser(description="Local-only demo server for bot-guard-py HTTP flood controls")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: loopback only)")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--per-client-rate", type=float, default=20.0, help="Sustained requests per second/client")
    parser.add_argument("--per-client-burst", type=int, default=60)
    parser.add_argument("--global-rate", type=float, default=1000.0, help="Sustained total requests per second")
    parser.add_argument("--global-burst", type=int, default=2000)
    parser.add_argument("--max-concurrent", type=int, default=500)
    args = parser.parse_args()
    protector = DDoSProtector(
        per_client_rate=args.per_client_rate,
        per_client_burst=args.per_client_burst,
        global_rate=args.global_rate,
        global_burst=args.global_burst,
        max_concurrent=args.max_concurrent,
    )
    server = make_server(args.host, args.port, create_app(protector),
                         server_class=ThreadingWSGIServer, handler_class=QuietRequestHandler)
    print("Demo bound to http://{0}:{1} (local test server; not a DDoS edge)".format(args.host, server.server_port), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
