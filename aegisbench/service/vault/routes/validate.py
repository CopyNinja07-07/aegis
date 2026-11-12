from fastapi import APIRouter

from vault.core import validate

router = APIRouter()


@router.get("/api/v1/validate/email")
def check_email(value: str):
    return {"value": value, "valid": validate.is_email(value)}


@router.get("/api/v1/validate/slug")
def check_slug(value: str):
    return {"value": value, "valid": validate.is_slug(value)}
