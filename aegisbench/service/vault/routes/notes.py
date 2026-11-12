from fastapi import APIRouter

from vault.core import db

router = APIRouter()


@router.get("/api/v1/notes/search")
def search(tenant: str, q: str):
    rows = db.search_notes(tenant, q)
    return {"count": len(rows), "notes": rows}
