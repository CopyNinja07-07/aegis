from fastapi import APIRouter

from vault.core import prefs

router = APIRouter()


@router.get("/api/v1/prefs/load")
def load(blob: str):
    return {"prefs": prefs.load_prefs(blob)}
