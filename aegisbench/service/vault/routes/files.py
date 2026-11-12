from fastapi import APIRouter

from vault.core import files

router = APIRouter()


@router.get("/api/v1/files/download")
def download(tenant: str, id: str):
    return {"file": files.download(tenant, id)}
