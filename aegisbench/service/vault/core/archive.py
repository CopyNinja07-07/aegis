"""Archive listings."""
import os

from vault.core.config import ARCHIVE_DIR


def list_archive(name: str) -> list[str]:
    root = os.path.realpath(ARCHIVE_DIR)
    path = os.path.realpath(os.path.join(root, name))
    if os.path.commonpath([root, path]) != root or not os.path.isdir(path):
        raise FileNotFoundError(name)
    return sorted(os.listdir(path))
