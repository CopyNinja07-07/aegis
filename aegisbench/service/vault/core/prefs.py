"""User preference blobs (base64-encoded)."""
import base64
import json


def load_prefs(blob: str) -> dict:
    data = json.loads(base64.b64decode(blob))
    if not isinstance(data, dict):
        raise ValueError("prefs must be an object")
    return data
