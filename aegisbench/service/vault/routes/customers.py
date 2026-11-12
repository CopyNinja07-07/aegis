from fastapi import APIRouter

from vault.core import db

router = APIRouter()


@router.get("/api/v1/customers/lookup")
def lookup(tenant: str, email: str):
    rows = db.find_customer(tenant, email)
    return {"count": len(rows), "accounts": rows}
