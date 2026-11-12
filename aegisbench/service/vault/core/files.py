"""Tenant file downloads."""
from vault.core import db
from vault.core.tenancy import require_same_tenant


def download(tenant: str, file_id: str) -> dict:
    record = require_same_tenant(db.get_file(file_id), tenant)
    return {"id": record["id"], "tenant_id": record["tenant_id"], "name": record["name"], "body": record["body"]}
