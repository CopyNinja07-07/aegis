"""The service's own regression tests (shared by every task)."""
from fastapi.testclient import TestClient

from vault.main import app

client = TestClient(app, raise_server_exceptions=False)


def test_health():
    assert client.get("/health").json() == {"status": "ok"}


def test_read_doc():
    r = client.get("/api/v1/docs/read", params={"name": "handbook.txt"})
    assert r.status_code == 200 and "handbook" in r.json()["content"]


def test_missing_doc_is_404():
    assert client.get("/api/v1/docs/read", params={"name": "nope.txt"}).status_code == 404


def test_customer_lookup():
    r = client.get("/api/v1/customers/lookup", params={"tenant": "tenant-a", "email": "asha@a.example"})
    assert r.json()["count"] == 1


def test_validate():
    assert client.get("/api/v1/validate/email", params={"value": "asha@a.example"}).json()["valid"] is True
    assert client.get("/api/v1/validate/slug", params={"value": "q3-report"}).json()["valid"] is True


def test_invoice_own_tenant():
    assert client.get("/api/v1/invoices/get", params={"tenant": "tenant-a", "id": "inv-1001"}).status_code == 200


def test_login_redirect_local():
    r = client.get("/api/v1/auth/login-redirect", params={"next": "/dashboard"}, follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == "/dashboard"
