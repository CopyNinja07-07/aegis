"""Document storage on local disk."""
import os

from vault.core.config import DOCS_DIR


def read_blob(name: str) -> str:
    safe = os.path.basename(name)
    path = os.path.join(DOCS_DIR, safe)
    if not os.path.isfile(path):
        raise FileNotFoundError(name)
    with open(path, "r", errors="ignore") as handle:
        return handle.read()
