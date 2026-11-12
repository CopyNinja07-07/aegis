"""Audit trail (distractor module)."""
import time

EVENTS: list[dict] = []


def record(kind: str, detail: str) -> None:
    EVENTS.append({"t": time.time(), "kind": kind, "detail": detail[:200]})
    del EVENTS[:-500]
