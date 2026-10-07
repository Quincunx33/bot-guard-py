"""Dependency-free generic ASGI and WSGI policy middleware."""
from ..models import BLOCK, CHALLENGE, RATE_LIMIT
from ..ddos import DDoSProtector


def _status(action, block_status):
    return 429 if action == RATE_LIMIT else block_status


def _body(action):
    message = "Request blocked by bot-guard-py." if action == BLOCK else "Additional verification required."
    return message.encode("utf-8")


def _send_asgi_rejection(send, status, message, retry_after=1):
    body = message.encode("utf-8")
    headers = [(b"content-type", b"text/plain; charset=utf-8"), (b"content-length", str(len(body)).encode("ascii")), (b"cache-control", b"no-store")]
    if retry_after is not None:
        headers.append((b"retry-after", str(max(1, int(retry_after + 0.999))).encode("ascii")))
    async def send_response():
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})
    return send_response()


def _asgi_peer_ip(scope):
    client = scope.get("client")
    return client[0] if client else None


def _wsgi_reject(start_response, status, message, retry_after=1):
    body = message.encode("utf-8")
    headers = [("Content-Type", "text/plain; charset=utf-8"), ("Content-Length", str(len(body))), ("Cache-Control", "no-store")]
    if retry_after is not None:
        headers.append(("Retry-After", str(max(1, int(retry_after + 0.999)))))
    phrase = "Too Many Requests" if status == 429 else "Service Unavailable" if status == 503 else "Forbidden"
    start_response("{0} {1}".format(status, phrase), headers)
    return [body]


class BotGuardASGI:
    def __init__(self, app, guard=None, on_action=None, *, block_status=403):
        from ..detector import BotGuard
        if not isinstance(block_status, int) or isinstance(block_status, bool) or not 100 <= block_status <= 599:
            raise ValueError("block_status must be an HTTP status code")
        self.app, self.guard, self.on_action, self.block_status = app, guard or BotGuard(), on_action, block_status

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)
        headers = {}
        for key, value in scope.get("headers", []):
            headers.setdefault(key.decode("latin-1").lower(), value.decode("latin-1"))
        client_ip = _asgi_peer_ip(scope)
        result = self.guard.inspect(headers, client_ip=client_ip, request_context=scope)
        scope["bot_guard_result"] = result
        if result.action in (BLOCK, CHALLENGE, RATE_LIMIT):
            if self.on_action is not None:
                response = self.on_action(result)
                if response is not None:
                    return await response(scope, receive, send)
            status = _status(result.action, self.block_status)
            body = _body(result.action)
            await send({"type": "http.response.start", "status": status, "headers": [(b"content-type", b"text/plain; charset=utf-8"), (b"content-length", str(len(body)).encode("ascii"))]})
            return await send({"type": "http.response.body", "body": body})
        return await self.app(scope, receive, send)


class BotGuardWSGI:
    def __init__(self, app, guard=None, on_action=None, *, block_status=403):
        from ..detector import BotGuard
        if not isinstance(block_status, int) or isinstance(block_status, bool) or not 100 <= block_status <= 599:
            raise ValueError("block_status must be an HTTP status code")
        self.app, self.guard, self.on_action, self.block_status = app, guard or BotGuard(), on_action, block_status

    def __call__(self, environ, start_response):
        headers = {key[5:].replace("_", "-").lower(): value for key, value in environ.items() if key.startswith("HTTP_")}
        result = self.guard.inspect(headers, client_ip=environ.get("REMOTE_ADDR"), request_context=environ)
        environ["bot_guard.result"] = result
        if result.action in (BLOCK, CHALLENGE, RATE_LIMIT):
            if self.on_action is not None:
                response = self.on_action(result)
                if response is not None:
                    return response(environ, start_response)
            status = _status(result.action, self.block_status)
            body = _body(result.action)
            phrase = "Too Many Requests" if status == 429 else "Forbidden" if status == 403 else "Policy Action"
            start_response("{0} {1}".format(status, phrase), [("Content-Type", "text/plain; charset=utf-8"), ("Content-Length", str(len(body)))])
            return [body]
        return self.app(environ, start_response)


class DDoSProtectionASGI:
    """Early ASGI HTTP flood control; must be mounted at the app boundary."""
    def __init__(self, app, protector=None, *, client_id_resolver=None):
        self.app = app
        self.protector = protector or DDoSProtector()
        self.client_id_resolver = client_id_resolver or _asgi_peer_ip

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)
        try:
            client_id = self.client_id_resolver(scope)
        except Exception:
            client_id = None
        user_agent = next((value.decode("latin-1") for key, value in scope.get("headers", []) if key.lower() == b"user-agent"), "")
        allowed, retry, reason = self.protector.check(client_id, user_agent=user_agent)
        if not allowed:
            status = 503 if reason == "limiter_error" else 429
            message = "Rate limiter is temporarily unavailable." if status == 503 else "Request rate limit exceeded."
            return await _send_asgi_rejection(send, status, message, retry)
        if not self.protector.try_enter():
            return await _send_asgi_rejection(send, 503, "Server is temporarily at capacity.", 1)
        try:
            return await self.app(scope, receive, send)
        finally:
            self.protector.leave()


class _SlotIterator:
    """Release a WSGI concurrency slot on exhaustion, error, or close."""
    def __init__(self, iterable, protector):
        self.iterable = iterable
        self.iterator = iter(iterable)
        self.protector = protector
        self.closed = False

    def __iter__(self):
        return self

    def __next__(self):
        try:
            return next(self.iterator)
        except StopIteration:
            self.close()
            raise
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            close = getattr(self.iterable, "close", None)
            if callable(close):
                close()
        finally:
            self.protector.leave()


class DDoSProtectionWSGI:
    """Early WSGI HTTP flood control with per-client/global rate and concurrency caps."""
    def __init__(self, app, protector=None, *, client_id_resolver=None):
        self.app = app
        self.protector = protector or DDoSProtector()
        self.client_id_resolver = client_id_resolver or (lambda environ: environ.get("REMOTE_ADDR"))

    def __call__(self, environ, start_response):
        try:
            client_id = self.client_id_resolver(environ)
        except Exception:
            client_id = None
        allowed, retry, reason = self.protector.check(client_id, user_agent=environ.get("HTTP_USER_AGENT", ""))
        if not allowed:
            status = 503 if reason == "limiter_error" else 429
            message = "Rate limiter is temporarily unavailable." if status == 503 else "Request rate limit exceeded."
            return _wsgi_reject(start_response, status, message, retry)
        if not self.protector.try_enter():
            return _wsgi_reject(start_response, 503, "Server is temporarily at capacity.", 1)
        try:
            response_iterable = self.app(environ, start_response)
        except BaseException:
            self.protector.leave()
            raise
        try:
            return _SlotIterator(response_iterable, self.protector)
        except BaseException:
            self.protector.leave()
            raise
