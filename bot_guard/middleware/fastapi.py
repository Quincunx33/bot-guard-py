"""Optional Starlette/FastAPI middleware with explicit policy actions."""
from ..detector import BotGuard
from ..models import BLOCK, CHALLENGE, RATE_LIMIT
from .generic import DDoSProtectionASGI as DDoSProtectionMiddleware
from .browser_signals import BrowserSignalASGI as BrowserSignalMiddleware


class BotGuardMiddleware:
    """Inspect HTTP requests and enforce the configured bot-policy action.

    ``on_action`` (or the backwards-compatible ``on_bot`` alias) may return an
    ASGI response callable to implement a challenge or custom rate limit.
    Without a handler, challenge and block actions return 403; rate-limit
    actions return 429. Only the socket peer address is used as client IP;
    forwarded headers must be handled by a trusted proxy layer.
    """

    def __init__(self, app, guard=None, on_bot=None, *, on_action=None, block_status=403):
        if not isinstance(block_status, int) or isinstance(block_status, bool) or not 100 <= block_status <= 599:
            raise ValueError("block_status must be an HTTP status code")
        if on_bot is not None and on_action is not None:
            raise ValueError("provide only one of on_bot or on_action")
        self.app = app
        self.guard = guard or BotGuard()
        self.on_action = on_action if on_action is not None else on_bot
        self.block_status = block_status

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)
        headers = {}
        for key, value in scope.get("headers", []):
            name = key.decode("latin-1").lower()
            headers.setdefault(name, value.decode("latin-1"))
        client = scope.get("client")
        client_ip = client[0] if client else None
        result = self.guard.inspect(headers, client_ip=client_ip, request_context=scope)
        scope["bot_guard_result"] = result
        if result.action in (BLOCK, CHALLENGE, RATE_LIMIT):
            if self.on_action is not None:
                response = self.on_action(result)
                if response is not None:
                    return await response(scope, receive, send)
            status = 429 if result.action == RATE_LIMIT else self.block_status
            body = ("Request blocked by bot-guard-py." if result.action == BLOCK else "Additional verification required.").encode("utf-8")
            await send({"type": "http.response.start", "status": status, "headers": [(b"content-type", b"text/plain; charset=utf-8"), (b"content-length", str(len(body)).encode("ascii"))]})
            return await send({"type": "http.response.body", "body": body})
        return await self.app(scope, receive, send)
