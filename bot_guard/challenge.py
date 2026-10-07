"""Dependency-free signed browser challenge and short-lived attestation helpers."""
import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from typing import Optional


class ChallengeManager:
    """Issue and verify expiring HMAC-signed proof-of-work challenges.

    Challenge proofs are accepted once per manager process. Multi-process or
    multi-host deployments need a shared replay store at the application layer.
    This is browser capability verification, not hardware-backed attestation.
    """
    def __init__(self, secret, *, difficulty=3, challenge_ttl=300, attestation_ttl=3600, max_used_challenges=10000):
        if isinstance(secret, str): secret = secret.encode("utf-8")
        if not isinstance(secret, bytes) or len(secret) < 16: raise ValueError("secret must contain at least 16 bytes")
        if not isinstance(difficulty, int) or isinstance(difficulty, bool) or not 1 <= difficulty <= 6: raise ValueError("difficulty must be between 1 and 6")
        if isinstance(challenge_ttl, bool) or challenge_ttl <= 0 or isinstance(attestation_ttl, bool) or attestation_ttl <= 0: raise ValueError("TTLs must be positive")
        if not isinstance(max_used_challenges, int) or isinstance(max_used_challenges, bool) or max_used_challenges < 1:
            raise ValueError("max_used_challenges must be a positive integer")
        self.secret, self.difficulty = secret, difficulty
        self.challenge_ttl, self.attestation_ttl = int(challenge_ttl), int(attestation_ttl)
        self.max_used_challenges = max_used_challenges
        self._used_challenges, self._replay_lock = {}, threading.Lock()

    def _sign(self, payload):
        raw = self._encode(payload)
        sig = hmac.new(self.secret, raw.encode("ascii"), hashlib.sha256).digest()
        return raw + "." + self._b64(sig)

    def _verify(self, token):
        try:
            raw, encoded_sig = token.split(".", 1)
            expected = hmac.new(self.secret, raw.encode("ascii"), hashlib.sha256).digest()
            if not hmac.compare_digest(expected, self._unb64(encoded_sig)): return None
            return json.loads(self._unb64(raw).decode("utf-8"))
        except (ValueError, TypeError, KeyError, json.JSONDecodeError, UnicodeDecodeError, AttributeError): return None

    @staticmethod
    def _b64(value): return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")
    @staticmethod
    def _unb64(value): return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    @classmethod
    def _encode(cls, payload): return cls._b64(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))

    def issue(self, client_id: Optional[str] = None):
        return self._sign({"typ": "challenge", "exp": int(time.time()) + self.challenge_ttl, "nonce": secrets.token_urlsafe(18), "client": client_id or "", "difficulty": self.difficulty})

    def verify(self, token, solution, client_id: Optional[str] = None):
        payload = self._verify(token)
        if not isinstance(payload, dict) or payload.get("typ") != "challenge": return False
        try:
            expires = int(payload.get("exp", 0))
            difficulty = int(payload.get("difficulty", 0))
        except (TypeError, ValueError, OverflowError):
            return False
        if expires < int(time.time()) or not 1 <= difficulty <= 6: return False
        if payload.get("client", "") != (client_id or ""): return False
        if not isinstance(solution, str) or len(solution) > 64: return False
        digest = hashlib.sha256((token + solution).encode("utf-8")).hexdigest()
        if not digest.startswith("0" * difficulty): return False

        return self._consume_once(token, expires)

    def _consume_once(self, token, expires):
        """Atomically consume a bounded, single-use token."""
        token_key = hashlib.sha256(token.encode("utf-8")).hexdigest()
        now = int(time.time())
        with self._replay_lock:
            expired = [key for key, exp in self._used_challenges.items() if exp < now]
            for key in expired:
                self._used_challenges.pop(key, None)
            if token_key in self._used_challenges or len(self._used_challenges) >= self.max_used_challenges:
                return False
            self._used_challenges[token_key] = expires
        return True

    def issue_attestation(self, client_id: Optional[str] = None):
        return self._sign({"typ": "attestation", "exp": int(time.time()) + self.attestation_ttl, "client": client_id or "", "nonce": secrets.token_urlsafe(12)})

    def verify_attestation(self, token, client_id: Optional[str] = None):
        payload = self._verify(token)
        if not isinstance(payload, dict) or payload.get("typ") != "attestation": return False
        try:
            expires = int(payload.get("exp", 0))
        except (TypeError, ValueError, OverflowError):
            return False
        return expires >= int(time.time()) and payload.get("client", "") == (client_id or "")

    def issue_browser_probe(self, client_id: Optional[str] = None):
        """Issue a one-use nonce for browser telemetry, bound to the peer IP."""
        return self._sign({"typ": "browser-probe", "exp": int(time.time()) + self.challenge_ttl,
                           "client": client_id or "", "nonce": secrets.token_urlsafe(18),
                           "difficulty": self.difficulty})

    def browser_probe_difficulty(self, token, client_id: Optional[str] = None):
        payload = self._verify(token)
        if not isinstance(payload, dict) or payload.get("typ") != "browser-probe":
            return None
        try:
            expires = int(payload.get("exp", 0))
            difficulty = int(payload.get("difficulty", 0))
        except (TypeError, ValueError, OverflowError):
            return None
        if (expires < int(time.time()) or payload.get("client", "") != (client_id or "")
                or not 1 <= difficulty <= 6):
            return None
        return difficulty

    def verify_browser_probe(self, token, solution, client_id: Optional[str] = None):
        difficulty = self.browser_probe_difficulty(token, client_id)
        if difficulty is None or not isinstance(solution, str) or len(solution) > 64:
            return False
        digest = hashlib.sha256((token + solution).encode("utf-8")).hexdigest()
        if not digest.startswith("0" * difficulty):
            return False
        payload = self._verify(token)
        if not isinstance(payload, dict):
            return False
        try:
            expires = int(payload.get("exp", 0))
        except (TypeError, ValueError, OverflowError):
            return False
        return self._consume_once(token, expires)

    def issue_browser_attestation(self, client_id: Optional[str] = None, *,
                                  automation_detected=True, interaction_count=0):
        """Sign short-lived, bounded browser telemetry for an HttpOnly cookie."""
        if not isinstance(automation_detected, bool):
            raise TypeError("automation_detected must be a bool")
        if (not isinstance(interaction_count, int) or isinstance(interaction_count, bool)
                or not 0 <= interaction_count <= 10000):
            raise ValueError("interaction_count must be an integer between 0 and 10000")
        return self._sign({"typ": "browser-signal", "exp": int(time.time()) + self.attestation_ttl,
                           "client": client_id or "", "automation": automation_detected,
                           "interactions": interaction_count, "nonce": secrets.token_urlsafe(12)})

    def read_browser_attestation(self, token, client_id: Optional[str] = None):
        payload = self._verify(token)
        if not isinstance(payload, dict) or payload.get("typ") != "browser-signal":
            return None
        try:
            expires = int(payload.get("exp", 0))
        except (TypeError, ValueError, OverflowError):
            return None
        if expires < int(time.time()) or payload.get("client", "") != (client_id or ""):
            return None
        if (not isinstance(payload.get("automation"), bool)
                or not isinstance(payload.get("interactions"), int)
                or isinstance(payload.get("interactions"), bool)
                or not 0 <= payload["interactions"] <= 10000):
            return None
        return payload

    def verify_browser_attestation(self, token, client_id: Optional[str] = None):
        payload = self.read_browser_attestation(token, client_id)
        return payload is not None and payload.get("automation") is True

    @staticmethod
    def _js_json(value):
        """Serialize a value for inline script without allowing script breakout."""
        return (json.dumps(value, ensure_ascii=True)
                .replace("<", "\\u003c")
                .replace(">", "\\u003e")
                .replace("&", "\\u0026")
                .replace("\u2028", "\\u2028")
                .replace("\u2029", "\\u2029"))

    def render(self, token, *, verify_url="/__bot_guard/verify", next_url="/"):
        """Render the browser proof page with script-context-safe JSON values."""
        safe_token = self._js_json(token)
        safe_verify = self._js_json(verify_url)
        safe_next = self._js_json(next_url)
        return """<!doctype html><meta charset="utf-8"><title>Verification</title><p>Verifying your browser…</p><script>
(async()=>{{const token={0},target={1},nextUrl={2},difficulty={3};let n=0;
while(true){{const b=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(token+n));const h=[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');if(h.startsWith('0'.repeat(difficulty)))break;n++;}}
const r=await fetch(target,{{method:'POST',headers:{{'Content-Type':'application/x-www-form-urlencoded'}},body:'token='+encodeURIComponent(token)+'&solution='+n+'&next='+encodeURIComponent(nextUrl)}});if(r.redirected)location.href=r.url;else document.body.innerText=await r.text();}})().catch(e=>document.body.innerText='Verification failed');</script>""".format(safe_token, safe_verify, safe_next, self.difficulty)
