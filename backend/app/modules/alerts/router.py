from fastapi import APIRouter, Depends

from app.core.dependencies import CurrentUser, require_roles
from app.modules.alerts.schemas import Alert
from app.modules.alerts.service import alerts_service

router = APIRouter()


@router.get('/', response_model=list[Alert])
def list_alerts(
    _user: CurrentUser = Depends(require_roles('Security Analyst', 'SOC Team Member', 'Administrator')),
) -> list[Alert]:
    return alerts_service.list_alerts()
