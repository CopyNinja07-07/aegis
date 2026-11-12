"""Vault: the multi-module FastAPI service that AegisBench tasks are planted in.
Routes are thin; the logic lives in vault/core, so localising a bug means following calls."""
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from vault.core.net import NetworkError
from vault.core.tenancy import TenantError
from vault.routes import auth, customers, docs, files, greet, invoices, notes, ops, prefs, preview, reports, validate

app = FastAPI(title="Vault")
for module in (docs, reports, customers, notes, validate, ops, preview, auth, invoices, files, prefs, greet):
    app.include_router(module.router)


@app.get("/health")
def health():
    return {"status": "ok"}


def _error(status: int, message: str) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status)


@app.exception_handler(FileNotFoundError)
async def not_found(_: Request, exc: Exception):
    return _error(404, "not found")


@app.exception_handler(TenantError)
async def tenant(_: Request, exc: Exception):
    return _error(404, "not found")


@app.exception_handler(NetworkError)
async def unreachable(_: Request, exc: Exception):
    return _error(404, "unreachable")


@app.exception_handler(PermissionError)
async def forbidden(_: Request, exc: Exception):
    return _error(403, "forbidden")


@app.exception_handler(ValueError)
async def bad_request(_: Request, exc: Exception):
    return _error(400, "bad request")
