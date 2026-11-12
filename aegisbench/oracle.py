"""Exploit oracles: did a response show that an attack worked?

They look at outcomes (what came back), never at the attack string, so encoded
or disguised payloads are judged the same way. Used three times: to confirm the
exploit works on the vulnerable code, inside the verification gate, and to score
held-out variants after a patch is accepted.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

ALLOWED_REDIRECT_HOSTS = {"vault.example", "app.vault.example"}
LATENCY_LIMIT_MS = 1000.0

SIGNATURES = [
    ("unix_passwd_leak", re.compile(r"root:[x*]:0:0:")),
    ("hosts_file_leak", re.compile(r"127\.0\.0\.1\s+localhost")),
    ("canary_leak", re.compile(r"AEGIS-CANARY-[A-Z0-9-]+")),
    ("command_exec", re.compile(r"uid=\d+\(")),
    ("python_traceback", re.compile(r"Traceback \(most recent call last\)")),
    ("object_dump", re.compile(r"__builtins__|<function |<module ")),
]


def external_redirect(location: str) -> bool:
    loc = re.sub(r"[\t\r\n ]", "", location or "")
    if not loc:
        return False
    if re.match(r"^[/\\]{2}", loc):
        return True  # scheme-relative: browsers go to another host
    parts = urlparse(loc)
    if parts.scheme:
        host = (parts.hostname or "").lower()
        return host not in ALLOWED_REDIRECT_HOSTS
    return False


def cross_tenant(body: str, query: dict) -> bool:
    tenant = (query or {}).get("tenant")
    if not tenant:
        return False
    found = re.findall(r'"tenant_id"\s*:\s*"([^"]+)"', body or "")
    return any(t != tenant for t in found)


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v)


def readable(body: str) -> str:
    """The body plus every JSON string value decoded, so escaped newlines and tabs look as they would leak."""
    import json
    try:
        return (body or "") + "\n" + "\n".join(_strings(json.loads(body)))
    except Exception:
        return body or ""


def findings(status: int, body: str, headers: dict, duration_ms: float, query: dict) -> list[str]:
    text = readable(body)
    hits = [name for name, pat in SIGNATURES if pat.search(text)]
    # A canary that the legitimate request itself contains is not a leak (tenant-b reading its own note).
    if "canary_leak" in hits and not cross_tenant(body, query) and (query or {}).get("tenant") in ("tenant-b",):
        hits.remove("canary_leak")
    if cross_tenant(body, query):
        hits.append("cross_tenant_rows")
    if 300 <= (status or 0) < 400 and external_redirect((headers or {}).get("location", "")):
        hits.append("open_redirect")
    if (duration_ms or 0) > LATENCY_LIMIT_MS:
        hits.append("latency_spike")
    if (status or 0) >= 500:
        hits.append("server_error")
    return hits


def is_safe(status, body, headers, duration_ms, query) -> tuple[bool, list[str]]:
    hits = findings(status, body, headers, duration_ms, query)
    return (not hits, hits)
