"""Privacy-aware deterministic fingerprints for short-lived correlation only."""
import hashlib
from collections.abc import Mapping

_DEFAULT_FIELDS = ("user-agent", "accept", "accept-language", "accept-encoding", "sec-ch-ua", "sec-fetch-dest")


def fingerprint(headers, *, salt="", fields=_DEFAULT_FIELDS, max_value_length=4096):
    """Return a non-reversible SHA-256 fingerprint of selected normalized headers."""
    if headers is None:
        headers = {}
    if not isinstance(headers, Mapping):
        raise TypeError("headers must be a mapping or None")
    if not isinstance(max_value_length, int) or max_value_length < 1:
        raise ValueError("max_value_length must be a positive integer")
    normalized = {str(k).lower(): str(v).strip().lower()[:max_value_length] for k, v in headers.items() if v is not None}
    payload = "\x1f".join(str(salt) + "\x1e" + str(name).lower() + "=" + normalized.get(str(name).lower(), "") for name in fields)
    return hashlib.sha256(payload.encode("utf-8", "surrogatepass")).hexdigest()
