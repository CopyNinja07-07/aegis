"""Report templates."""
import os

from vault.core.config import TEMPLATES_DIR


def load_template(name: str) -> str:
    root = os.path.realpath(TEMPLATES_DIR)
    path = os.path.realpath(os.path.join(root, name))
    if os.path.commonpath([root, path]) != root or not os.path.isfile(path):
        raise FileNotFoundError(name)
    with open(path) as handle:
        return handle.read()


def render(name: str, title: str) -> str:
    return load_template(name).replace("{{title}}", title)
