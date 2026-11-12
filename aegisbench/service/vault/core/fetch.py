"""Link previews for documents."""
from urllib.parse import urlparse

from vault.core.config import ALLOWED_FETCH_HOSTS
from vault.core.net import http_get


def preview(url: str) -> str:
    parts = urlparse(url)
    if parts.scheme != "https" or parts.hostname not in ALLOWED_FETCH_HOSTS:
        raise PermissionError("host not allowed")
    return http_get(parts.hostname, parts.path or "/")[:200]


def read_asset(url: str) -> str:
    parts = urlparse(url)
    if parts.scheme != "https" or parts.hostname not in ALLOWED_FETCH_HOSTS:
        raise PermissionError("scheme or host not allowed")
    return http_get(parts.hostname, parts.path or "/")[:200]
