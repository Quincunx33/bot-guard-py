"""Optional Django middleware with bot-policy and HTTP-flood controls."""
from ..detector import BotGuard
from ..ddos import DDoSProtector
from ..models import BLOCK, CHALLENGE, RATE_LIMIT


class BotGuardMiddleware:
    def __init__(self, get_response, guard=None, on_action=None, *, block_status=403):
        if not isinstance(block_status, int) or isinstance(block_status, bool) or not 100 <= block_status <= 599:
            raise ValueError("block_status must be an HTTP status code")
        self.get_response = get_response
        self.guard = guard or BotGuard()
        self.on_action = on_action
        self.block_status = block_status

    def __call__(self, request):
        from django.http import HttpResponse
        result = self.guard.inspect(request.headers, client_ip=request.META.get("REMOTE_ADDR"), request_context=request)
        request.bot_guard_result = result
        if result.action in (BLOCK, CHALLENGE, RATE_LIMIT):
            if self.on_action is not None:
                response = self.on_action(result)
                if response is not None:
                    return response
            status = 429 if result.action == RATE_LIMIT else self.block_status
            message = "Request blocked by bot-guard-py." if result.action == BLOCK else "Additional verification required."
            return HttpResponse(message, status=status)
        return self.get_response(request)


class DDoSProtectionMiddleware:
    """Django HTTP-flood middleware; configure trusted-proxy IP extraction."""
    def __init__(self, get_response, protector=None, client_id_resolver=None):
        from django.conf import settings
        self.get_response = get_response
        self.protector = protector or getattr(settings, "BOT_GUARD_DDOS_PROTECTOR", None) or DDoSProtector()
        self.client_id_resolver = client_id_resolver or getattr(settings, "BOT_GUARD_DDOS_CLIENT_ID_RESOLVER", None)

    def __call__(self, request):
        from django.http import HttpResponse
        try:
            client_id = self.client_id_resolver(request) if self.client_id_resolver else request.META.get("REMOTE_ADDR")
        except Exception:
            client_id = None
        allowed, retry, reason = self.protector.check(client_id)
        if not allowed:
            status = 503 if reason == "limiter_error" else 429
            message = "Rate limiter is temporarily unavailable." if status == 503 else "Request rate limit exceeded."
            response = HttpResponse(message, status=status)
            response["Retry-After"] = str(max(1, int(retry + 0.999)))
            response["Cache-Control"] = "no-store"
            return response
        if not self.protector.try_enter():
            response = HttpResponse("Server is temporarily at capacity.", status=503)
            response["Retry-After"] = "1"
            response["Cache-Control"] = "no-store"
            return response
        try:
            return self.get_response(request)
        finally:
            self.protector.leave()
