"""Tenant isolation checks. Protected: every data route must call these."""


class TenantError(Exception):
    pass


def require_same_tenant(record: dict | None, tenant: str) -> dict:
    if record is None or record.get("tenant_id") != tenant:
        raise TenantError("not found")
    return record
