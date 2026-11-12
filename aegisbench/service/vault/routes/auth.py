from fastapi import APIRouter
from fastapi.responses import RedirectResponse

from vault.core import redirect

router = APIRouter()


@router.get("/api/v1/auth/login-redirect")
def login_redirect(next: str = "/home"):
    return RedirectResponse(redirect.safe_next(next), status_code=302)


@router.get("/api/v1/auth/logout")
def logout(next: str = "/home"):
    return RedirectResponse(redirect.logout_target(next), status_code=302)
