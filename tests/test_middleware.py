import asyncio
import sys
import types
import unittest
from types import SimpleNamespace
from unittest import mock

from bot_guard import BotGuard
from bot_guard.middleware.fastapi import BotGuardMiddleware as FastAPIMiddleware
from bot_guard.middleware.flask import init_bot_guard
from bot_guard.middleware.generic import BotGuardASGI, BotGuardWSGI
from bot_guard.middleware.django import BotGuardMiddleware as DjangoMiddleware
from bot_guard.models import RATE_LIMIT


class FixedProvider:
    def score(self, headers, client_ip=None):
        return 1.0


class MiddlewareTests(unittest.TestCase):
    def _asgi_request(self, middleware, *, client=("192.0.2.9", 1234), headers=None):
        messages = []
        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}
        async def send(message):
            messages.append(message)
        scope = {"type": "http", "asgi": {"version": "3.0"}, "method": "GET", "path": "/", "headers": headers or [], "client": client}
        async def run():
            await middleware(scope, receive, send)
        asyncio.run(run())
        return scope, messages

    def test_fastapi_adapter_uses_peer_ip_for_denylist(self):
        downstream = []
        async def app(scope, receive, send):
            downstream.append(True)
        middleware = FastAPIMiddleware(app, BotGuard(deny_ips=["192.0.2.0/24"]))
        scope, messages = self._asgi_request(middleware)
        self.assertFalse(downstream)
        self.assertEqual(messages[0]["status"], 403)
        self.assertEqual(scope["bot_guard_result"].action, "BLOCK")

    def test_fastapi_adapter_returns_429_and_invokes_action_handler(self):
        seen = []
        async def app(scope, receive, send):
            seen.append("downstream")
        async def custom_response(scope, receive, send):
            seen.append("custom")
            await send({"type": "http.response.start", "status": 202, "headers": []})
            await send({"type": "http.response.body", "body": b"handled"})
        guard = BotGuard(threshold=.9, challenge_at=.1, rate_limit_at=.2, block_at=.8, reputation_provider=FixedProvider())
        middleware = FastAPIMiddleware(app, guard, on_action=lambda result: custom_response if result.action == RATE_LIMIT else None)
        _, messages = self._asgi_request(middleware)
        self.assertEqual(seen, ["custom"])
        self.assertEqual(messages[0]["status"], 202)

    def test_generic_asgi_passes_peer_ip_and_default_rate_limit_status(self):
        guard = BotGuard(threshold=.9, challenge_at=.1, rate_limit_at=.2, block_at=.8, reputation_provider=FixedProvider())
        middleware = BotGuardASGI(lambda *args: None, guard)
        _, messages = self._asgi_request(middleware)
        self.assertEqual(messages[0]["status"], 429)

    def test_wsgi_peer_ip_denylist_and_action_callback(self):
        callback_called = []
        def handler(result):
            callback_called.append(result.action)
            def response(environ, start_response):
                start_response("202 Accepted", [("Content-Length", "0")])
                return [b""]
            return response
        middleware = BotGuardWSGI(lambda env, start: [b"downstream"], BotGuard(deny_ips=["192.0.2.0/24"]), handler)
        captured = []
        result = middleware({"REMOTE_ADDR": "192.0.2.9"}, lambda status, headers: captured.append(status))
        self.assertEqual(callback_called, ["BLOCK"])
        self.assertEqual(captured, ["202 Accepted"])
        self.assertEqual(result, [b""])

    def test_allowlisted_peer_reaches_application(self):
        downstream = []
        async def app(scope, receive, send):
            downstream.append(True)
        middleware = FastAPIMiddleware(app, BotGuard(allow_ips=["192.0.2.0/24"]))
        self._asgi_request(middleware)
        self.assertTrue(downstream)

    def test_flask_adapter_uses_peer_ip_and_rate_limit_action(self):
        class App:
            def before_request(self, callback):
                self.callback = callback
        fake_flask = types.ModuleType("flask")
        fake_flask.g = SimpleNamespace()
        fake_flask.request = SimpleNamespace(headers={}, remote_addr="192.0.2.9")
        fake_flask.make_response = lambda body, status: (body, status)
        app = App()
        guard = BotGuard(threshold=.9, challenge_at=.1, rate_limit_at=.2, block_at=.8, reputation_provider=FixedProvider())
        with mock.patch.dict(sys.modules, {"flask": fake_flask}):
            init_bot_guard(app, guard)
            response = app.callback()
        self.assertEqual(response[1], 429)
        self.assertEqual(fake_flask.g.bot_guard_result.action, RATE_LIMIT)

    def test_django_adapter_uses_remote_addr_for_ip_denylist(self):
        fake_django = types.ModuleType("django")
        fake_django.__path__ = []
        fake_http = types.ModuleType("django.http")
        fake_http.HttpResponse = lambda body, status: (body, status)
        request = SimpleNamespace(headers={}, META={"REMOTE_ADDR": "192.0.2.9"})
        with mock.patch.dict(sys.modules, {"django": fake_django, "django.http": fake_http}):
            middleware = DjangoMiddleware(lambda req: "downstream", BotGuard(deny_ips=["192.0.2.0/24"]))
            response = middleware(request)
        self.assertEqual(response[1], 403)
        self.assertEqual(request.bot_guard_result.action, "BLOCK")


if __name__ == "__main__":
    unittest.main()
