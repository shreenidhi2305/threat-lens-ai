from app.modules.alerts.schemas import Alert


class AlertsService:
    def list_alerts(self) -> list[Alert]:
        return []


alerts_service = AlertsService()
