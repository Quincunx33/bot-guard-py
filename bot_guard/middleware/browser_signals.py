"""WSGI/ASGI endpoints for the opt-in browser automation probe."""
from http.cookies import CookieError, SimpleCookie


def _client_ip(scope):
    client = scope.get("client")
    return client[0] if client else None


def _cookie_value(raw_cookie, name):
    cookie = SimpleCookie()
    try:
        cookie.load(raw_cookie or "")
        morsel = cookie.get(name)
    except (CookieError, TypeError, ValueError):
        return None
    return morsel.value if morsel is not None else None


def _cookie_header(name, token, ttl, secure=False):
    value = "{0}={1}; Path=/; Max-Age={2}; HttpOnly; SameSite=Lax".format(name, token, ttl)
    if secure:
        value += "; Secure"
    return value


def _validate_endpoint(path):
    if (not isinstance(path, str) or not path.startswith("/") or path.startswith("//")
            or any(ch in path for ch in "\\?#\r\n")):
        raise ValueError("browser signal endpoints must be same-origin absolute paths")


def _script_headers(body):
    return [(b"content-type", b"application/javascript; charset=utf-8"),
            (b"x-content-type-options", b"nosniff")]


def _asgi_response(send, status, body=b"", headers=None):
    values = [(b"content-length", str(len(body)).encode("ascii")),
              (b"cache-control", b"no-store")]
    if headers:
        values.extend(headers)
    async def send_response():
        await send({"type": "http.response.start", "status": status, "headers": values})
        await send({"type": "http.response.body", "body": body})
    return send_response()


class BrowserSignalASGI:
    """Serve probe JavaScript and accept its signed, single-use telemetry."""
    def __init__(self, app, signal_manager, *, client_id_resolver=None,
                 script_path="/__bot_guard/probe.js", signal_path="/__bot_guard/signal",
                 max_body_bytes=4096):
        if not isinstance(max_body_bytes, int) or isinstance(max_body_bytes, bool) or max_body_bytes < 256:
            raise ValueError("max_body_bytes must be an integer of at least 256")
        _validate_endpoint(script_path)
        _validate_endpoint(signal_path)
        if script_path == signal_path:
            raise ValueError("script_path and signal_path must differ")
        self.app, self.manager = app, signal_manager
        self.client_id_resolver = client_id_resolver or _client_ip
        self.script_path, self.signal_path = script_path, signal_path
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)
        path, method = scope.get("path", "/"), scope.get("method", "GET").upper()
        try:
            client_id = self.client_id_resolver(scope)
        except Exception:
            client_id = None
        headers = {}
        for key, value in scope.get("headers", []):
            headers.setdefault(key.decode("latin-1").lower(), value.decode("latin-1"))

        if path == self.script_path and method == "GET":
            body = self.manager.render_script(client_id, post_url=self.signal_path).encode("utf-8")
            return await _asgi_response(send, 200, body, _script_headers(body))
        if path == self.signal_path and method == "POST":
            content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
            if content_type != "application/json":
                return await _asgi_response(send, 415, b"Expected application/json")
            chunks, length = [], 0
            while True:
                message = await receive()
                if message.get("type") == "http.disconnect":
                    return await _asgi_response(send, 400, b"Incomplete request")
                chunk = message.get("body", b"")
                length += len(chunk)
                if length > self.max_body_bytes:
                    return await _asgi_response(send, 413, b"Signal body too large")
                chunks.append(chunk)
                if not message.get("more_body", False):
                    break
            try:
                payload = self.manager.parse_payload(b"".join(chunks))
            except ValueError:
                return await _asgi_response(send, 400, b"Invalid browser signal")
            current_cookie = _cookie_value(headers.get("cookie"), self.manager.cookie_name)
            accepted = self.manager.accept(client_id, payload, current_cookie=current_cookie)
            if accepted is None:
                return await _asgi_response(send, 403, b"Invalid or expired browser probe")
            secure = scope.get("scheme") == "https"
            cookie = _cookie_header(self.manager.cookie_name, accepted["attestation"],
                                    self.manager.challenge_manager.attestation_ttl, secure)
            return await _asgi_response(send, 204, headers=[(b"set-cookie", cookie.encode("latin-1"))])
        return await self.app(scope, receive, send)


class BrowserSignalWSGI:
    """WSGI equivalent of :class:`BrowserSignalASGI`."""
    def __init__(self, app, signal_manager, *, client_id_resolver=None,
                 script_path="/__bot_guard/probe.js", signal_path="/__bot_guard/signal",
                 max_body_bytes=4096):
        if not isinstance(max_body_bytes, int) or isinstance(max_body_bytes, bool) or max_body_bytes < 256:
            raise ValueError("max_body_bytes must be an integer of at least 256")
        _validate_endpoint(script_path)
        _validate_endpoint(signal_path)
        if script_path == signal_path:
            raise ValueError("script_path and signal_path must differ")
        self.app, self.manager = app, signal_manager
        self.client_id_resolver = client_id_resolver or (lambda environ: environ.get("REMOTE_ADDR"))
        self.script_path, self.signal_path = script_path, signal_path
        self.max_body_bytes = max_body_bytes

    @staticmethod
    def _respond(start_response, status, body=b"", headers=None):
        values = [("Content-Length", str(len(body))), ("Cache-Control", "no-store")]
        if headers:
            values.extend(headers)
        phrase = {200: "OK", 204: "No Content", 400: "Bad Request", 403: "Forbidden",
                  413: "Payload Too Large", 415: "Unsupported Media Type"}.get(status, "Response")
        start_response("{0} {1}".format(status, phrase), values)
        return [body] if body else []

    def __call__(self, environ, start_response):
        path, method = environ.get("PATH_INFO", "/"), environ.get("REQUEST_METHOD", "GET").upper()
        try:
            client_id = self.client_id_resolver(environ)
        except Exception:
            client_id = None
        if path == self.script_path and method == "GET":
            body = self.manager.render_script(client_id, post_url=self.signal_path).encode("utf-8")
            headers = [(key.decode("ascii").title(), value.decode("ascii")) for key, value in _script_headers(body)]
            return self._respond(start_response, 200, body, headers)
        if path == self.signal_path and method == "POST":
            content_type = environ.get("CONTENT_TYPE", "").split(";", 1)[0].strip().lower()
            if content_type != "application/json":
                return self._respond(start_response, 415, b"Expected application/json")
            try:
                length = int(environ.get("CONTENT_LENGTH") or "0")
            except (TypeError, ValueError):
                return self._respond(start_response, 400, b"Invalid Content-Length")
            if length < 0:
                return self._respond(start_response, 400, b"Invalid Content-Length")
            if length > self.max_body_bytes:
                return self._respond(start_response, 413, b"Signal body too large")
            raw = environ.get("wsgi.input").read(length) if length else b""
            try:
                payload = self.manager.parse_payload(raw)
            except (ValueError, AttributeError):
                return self._respond(start_response, 400, b"Invalid browser signal")
            current_cookie = _cookie_value(environ.get("HTTP_COOKIE"), self.manager.cookie_name)
            accepted = self.manager.accept(client_id, payload, current_cookie=current_cookie)
            if accepted is None:
                return self._respond(start_response, 403, b"Invalid or expired browser probe")
            secure = environ.get("wsgi.url_scheme") == "https"
            cookie = _cookie_header(self.manager.cookie_name, accepted["attestation"],
                                    self.manager.challenge_manager.attestation_ttl, secure)
            return self._respond(start_response, 204, headers=[("Set-Cookie", cookie)])
        return self.app(environ, start_response)
