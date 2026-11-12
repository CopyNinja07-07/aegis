from fastapi import APIRouter

from vault.core import billing

router = APIRouter()


@router.get("/api/v1/invoices/get")
def get_invoice(tenant: str, id: str):
    return {"invoice": billing.invoice_for(tenant, id)}
