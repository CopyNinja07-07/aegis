"""Request counters (distractor module)."""
from collections import Counter

COUNTS: Counter = Counter()


def hit(route: str) -> int:
    COUNTS[route] += 1
    return COUNTS[route]
