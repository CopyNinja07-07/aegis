from fastapi import APIRouter

from vault.core import templates

router = APIRouter()


@router.get("/api/v1/reports/render")
def render_report(template: str, title: str = "Report"):
    return {"template": template, "body": templates.render(template, title)}
