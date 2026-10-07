"""Optional Flask adapters."""
from ..detector import BotGuard
from ..models import BLOCK, CHALLENGE, RATE_LIMIT


def init_bot_guard(app, guard=None, on_bot=None, *, on_action=None, block_status=403):
    """Install request inspection and enforce non-pass bot actions.

    ``on_bot`` is retained as a backwards-compatible alias for ``on_action``.
    A handler should return a Flask response for custom challenges/rate limits;
    return ``None`` to use the default response. ``request.remote_addr`` is
    trusted as the socket peer; configure proxy trust separately.
    """
    if not isinstance(block_status, int) or isinstance(block_status, bool) or not 100 <= block_status <= 599:
        raise ValueError("block_status must be an HTTP status code")
    if on_bot is not None and on_action is not None:
        raise ValueError("provide only one of on_bot or on_action")
    guard = guard or BotGuard()
    handler = on_action if on_action is not None else on_bot

    @app.before_request
    def _inspect_request():
        from flask import g, make_response, request
        result = guard.inspect(request.headers, client_ip=request.remote_addr, request_context=request)
        g.bot_guard_result = result
        if result.action in (BLOCK, CHALLENGE, RATE_LIMIT):
            if handler is not None:
                response = handler(result)
                if response is not None:
                    return response
            status = 429 if result.action == RATE_LIMIT else block_status
            message = "Request blocked by bot-guard-py." if result.action == BLOCK else "Additional verification required."
            return make_response(message, status)
        return None

    return app


def init_ddos_protection(app, protector=None, *, client_id_resolver=None):
    """Wrap Flask's WSGI boundary with rate and concurrency protection.

    For production behind a proxy, either configure proxy trust correctly or
    pass a resolver that extracts a client address only from trusted hops.
    """
    from .generic import DDoSProtectionWSGI
    app.wsgi_app = DDoSProtectionWSGI(app.wsgi_app, protector, client_id_resolver=client_id_resolver)
    return app
