from fastapi import APIRouter

from vault.core import greet

router = APIRouter()


@router.get("/api/v1/greet")
def banner(template: str, name: str):
    return {"banner": greet.banner(template, name)}
