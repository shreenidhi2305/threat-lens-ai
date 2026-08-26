from fastapi import APIRouter

from app.modules.threat_monitoring.schemas import ThreatSnapshot
from app.modules.threat_monitoring.service import threat_monitoring_service

router = APIRouter()


@router.get('/snapshot', response_model=ThreatSnapshot)
def snapshot() -> ThreatSnapshot:
    return threat_monitoring_service.get_snapshot()
