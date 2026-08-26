from fastapi import APIRouter

from app.modules.alerts.schemas import Alert
from app.modules.alerts.service import alerts_service

router = APIRouter()


@router.get('/', response_model=list[Alert])
def list_alerts() -> list[Alert]:
    return alerts_service.list_alerts()
