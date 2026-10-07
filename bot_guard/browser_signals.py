"""Signed browser-side automation telemetry; signals are heuristic, not attestation."""
import json
import re
from collections.abc import Mapping
from http.cookies import CookieError, SimpleCookie

from .challenge import ChallengeManager


_ALLOWED_MARKERS = frozenset({
    "domAutomationController", "webdriverScript", "seleniumCdc",
    "phantom", "playwrightBinding", "nightmare",
})


class BrowserSignalManager:
    """Issue one-use browser probes and validate signed telemetry cookies.

    ``navigator.webdriver`` and related properties are client-reported and can
    be hidden by stealth tooling. Treat a positive signal as a strong risk hint,
    not hardware-backed proof. Verified search-crawler IPs should be exempted in
    ``BotGuard`` before this provider is consulted.
    """
    def __init__(self, challenge_manager, *, cookie_name="__bot_guard_signal"):
        if not isinstance(challenge_manager, ChallengeManager):
            raise TypeError("challenge_manager must be a ChallengeManager")
        if not isinstance(cookie_name, str) or not re.fullmatch(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+", cookie_name):
            raise ValueError("cookie_name is invalid")
        self.challenge_manager = challenge_manager
        self.cookie_name = cookie_name

    def render_script(self, client_id, *, post_url="/__bot_guard/signal"):
        """Create a JS probe bound to the peer IP and posted back same-origin."""
        if (not isinstance(post_url, str) or not post_url.startswith("/") or post_url.startswith("//")
                or any(ch in post_url for ch in "\\?#\r\n")):
            raise ValueError("post_url must be a same-origin absolute path without query or fragment")
        token = self.challenge_manager.issue_browser_probe(client_id)
        difficulty = self.challenge_manager.browser_probe_difficulty(token, client_id)
        safe_token = self.challenge_manager._js_json(token)
        safe_url = self.challenge_manager._js_json(post_url)
        safe_difficulty = self.challenge_manager._js_json(difficulty)
        return r"""(()=>{{'use strict';
const token={0},url={1},difficulty={2};let interactions=0,sent=false;
const markers=[];
const checks=[
 ['domAutomationController',()=>('domAutomationController' in window)],
 ['webdriverScript',()=>('__webdriver_script_fn' in window)||('__webdriver_evaluate' in document)],
 ['seleniumCdc',()=>Object.keys(window).some(k=>k.startsWith('cdc_')&&k.toLowerCase().includes('automation'))],
 ['phantom',()=>Boolean(window.callPhantom||window._phantom)],
 ['playwrightBinding',()=>('__playwright__binding__' in window)],
 ['nightmare',()=>Boolean(window.__nightmare)]
];
for(const [name,test] of checks){{try{{if(test())markers.push(name)}}catch(_e){{}}}}
const signals={{webdriver:navigator.webdriver===true,automation_markers:markers,interaction_count:0}};
const activity=()=>{{interactions=Math.min(10000,interactions+1)}};
for(const event of ['pointerdown','keydown','touchstart','wheel']){{window.addEventListener(event,activity,{{capture:true,passive:true,once:true}})}}
const solve=async()=>{{let n=0;for(;;n++){{const bytes=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(token+n));
const hash=[...new Uint8Array(bytes)].map(x=>x.toString(16).padStart(2,'0')).join('');
if(hash.startsWith('0'.repeat(difficulty)))return String(n);}}}};
const send=async()=>{{if(sent)return;sent=true;signals.interaction_count=interactions;const solution=await solve();
await fetch(url,{{method:'POST',credentials:'same-origin',keepalive:true,
headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{token,solution,signals}})}});
}};
window.setTimeout(()=>{{send().catch(()=>{{}});}},1000);
}})();""".format(safe_token, safe_url, safe_difficulty)

    def accept(self, client_id, payload, *, current_cookie=None):
        """Validate a single-use probe and return signed-cookie data or None."""
        if not isinstance(payload, Mapping):
            return None
        token = payload.get("token")
        solution = payload.get("solution")
        signals = payload.get("signals")
        if (not isinstance(token, str) or len(token) > 4096 or not isinstance(solution, str)
                or len(solution) > 64 or not isinstance(signals, Mapping)):
            return None
        webdriver = signals.get("webdriver")
        markers = signals.get("automation_markers", [])
        interactions = signals.get("interaction_count", 0)
        if not isinstance(webdriver, bool):
            return None
        if (not isinstance(markers, list) or len(markers) > len(_ALLOWED_MARKERS)
                or any(not isinstance(marker, str) or marker not in _ALLOWED_MARKERS for marker in markers)):
            return None
        if (not isinstance(interactions, int) or isinstance(interactions, bool)
                or not 0 <= interactions <= 10000):
            return None
        if not self.challenge_manager.verify_browser_probe(token, solution, client_id):
            return None

        detected = webdriver or bool(markers)
        # Do not let a later negative report erase a still-valid positive cookie.
        prior = self.challenge_manager.read_browser_attestation(current_cookie, client_id) if current_cookie else None
        if prior is not None and prior.get("automation"):
            detected = True
            interactions = max(interactions, prior.get("interactions", 0))
        attestation = self.challenge_manager.issue_browser_attestation(
            client_id, automation_detected=detected, interaction_count=interactions)
        return {"automation_detected": detected, "interaction_count": interactions,
                "attestation": attestation}

    def is_automated(self, headers, client_id):
        """BotGuard provider hook: validate a signed HttpOnly browser cookie."""
        raw_cookie = headers.get("cookie", "") if isinstance(headers, Mapping) else ""
        cookie = SimpleCookie()
        try:
            cookie.load(raw_cookie)
            morsel = cookie.get(self.cookie_name)
        except (CookieError, TypeError, ValueError):
            return False
        if morsel is None:
            return False
        return self.challenge_manager.verify_browser_attestation(morsel.value, client_id)

    @staticmethod
    def parse_payload(raw):
        """Parse bounded UTF-8 JSON from the signal endpoint."""
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        if not isinstance(raw, str) or len(raw) > 8192:
            raise ValueError("signal body is invalid or too large")
        try:
            payload = json.loads(raw)
        except (ValueError, TypeError) as exc:
            raise ValueError("signal body must be valid JSON") from exc
        if not isinstance(payload, Mapping):
            raise ValueError("signal body must be a JSON object")
        return payload
