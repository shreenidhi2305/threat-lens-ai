from pydantic import BaseModel


class ThreatSnapshot(BaseModel):
    active_alerts: int
    high_risk_samples: int
