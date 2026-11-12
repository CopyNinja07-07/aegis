from fastapi import APIRouter

from vault.core import archive, shell

router = APIRouter()


@router.get("/api/v1/ops/status")
def status(host: str):
    return {"host": host, "output": shell.echo_status(host)}


@router.get("/api/v1/ops/archive")
def list_archive(name: str):
    return {"name": name, "entries": archive.list_archive(name)}
