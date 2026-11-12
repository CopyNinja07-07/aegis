"""Operational helpers that call system tools."""
import subprocess


def echo_status(host: str) -> str:
    result = subprocess.run(["echo", "checking", host], capture_output=True, text=True, timeout=5)
    return result.stdout.strip()
