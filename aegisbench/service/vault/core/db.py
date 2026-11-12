"""Customer and notes database (SQLite)."""
import sqlite3

from vault.core.config import DB_PATH


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def find_customer(tenant: str, email: str) -> list[dict]:
    with connect() as conn:
        rows = conn.execute("SELECT id, tenant_id, full_name, email FROM customers WHERE tenant_id = ? AND email = ?",
                            (tenant, email)).fetchall()
    return [dict(r) for r in rows]


def search_notes(tenant: str, query: str) -> list[dict]:
    with connect() as conn:
        rows = conn.execute("SELECT id, tenant_id, body FROM notes WHERE tenant_id = ? AND body LIKE ?",
                            (tenant, f"%{query}%")).fetchall()
    return [dict(r) for r in rows]


def get_invoice(invoice_id: str) -> dict | None:
    with connect() as conn:
        row = conn.execute("SELECT id, tenant_id, amount, status FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
    return dict(row) if row else None


def get_file(file_id: str) -> dict | None:
    with connect() as conn:
        row = conn.execute("SELECT id, tenant_id, name, body FROM files WHERE id = ?", (file_id,)).fetchone()
    return dict(row) if row else None
