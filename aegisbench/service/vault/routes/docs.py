from fastapi import APIRouter

from vault.core import storage

router = APIRouter()


@router.get("/api/v1/docs/read")
def read_doc(name: str):
    return {"name": name, "content": storage.read_blob(name)}
