from fastapi import APIRouter

from vault.core import fetch

router = APIRouter()


@router.get("/api/v1/preview")
def link_preview(url: str):
    return {"url": url, "preview": fetch.preview(url)}


@router.get("/api/v1/assets")
def asset(url: str):
    return {"url": url, "content": fetch.read_asset(url)}
