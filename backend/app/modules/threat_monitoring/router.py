from fastapi import APIRouter, Depends

from app.core.dependencies import CurrentUser, require_roles
from app.modules.threat_monitoring.schemas import ThreatSnapshot
from app.modules.threat_monitoring.service import threat_monitoring_service

router = APIRouter()


@router.get('/snapshot', response_model=ThreatSnapshot)
def snapshot(
    _user: CurrentUser = Depends(require_roles('Security Analyst', 'SOC Team Member', 'Administrator')),
) -> ThreatSnapshot:
    return threat_monitoring_service.get_snapshot()
