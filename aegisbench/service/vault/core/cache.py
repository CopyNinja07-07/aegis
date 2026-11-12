"""Tiny in-process cache (distractor module)."""
_STORE: dict[str, str] = {}


def get(key: str) -> str | None:
    return _STORE.get(key)


def put(key: str, value: str) -> None:
    if len(_STORE) > 1000:
        _STORE.clear()
    _STORE[key] = value
