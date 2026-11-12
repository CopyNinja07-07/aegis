"""Post-login redirects."""
from urllib.parse import urlparse

from vault.core.config import ALLOWED_REDIRECT_HOSTS


def safe_next(target: str) -> str:
    parts = urlparse(target)
    if parts.scheme == "" and parts.netloc == "" and target.startswith("/") and not target.startswith("//"):
        return target
    if parts.scheme == "https" and parts.hostname in ALLOWED_REDIRECT_HOSTS:
        return target
    return "/home"


def logout_target(target: str) -> str:
    return safe_next(target)
