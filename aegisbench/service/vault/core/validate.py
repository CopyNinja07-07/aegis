"""Input validation."""
import re

EMAIL = re.compile(r"^[a-zA-Z0-9]+(?:\.[a-zA-Z0-9]+)*@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,}$")
SLUG = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def is_email(value: str) -> bool:
    return len(value) <= 254 and bool(EMAIL.match(value))


def is_slug(value: str) -> bool:
    return len(value) <= 64 and bool(SLUG.match(value))
