from app.modules.threat_monitoring.schemas import ThreatSnapshot


class ThreatMonitoringService:
    def get_snapshot(self) -> ThreatSnapshot:
        return ThreatSnapshot(active_alerts=0, high_risk_samples=0)


threat_monitoring_service = ThreatMonitoringService()
