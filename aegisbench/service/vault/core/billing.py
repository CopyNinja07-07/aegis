"""Invoice views."""
from vault.core import db
from vault.core.tenancy import require_same_tenant


def invoice_for(tenant: str, invoice_id: str) -> dict:
    return require_same_tenant(db.get_invoice(invoice_id), tenant)
