from datetime import datetime

from pydantic import BaseModel


class Detection(BaseModel):
    """One entry in the detection log - written for every analysed file."""

    id: str
    at: datetime
    sha256: str
    filename: str
    verdict_label: str
    score: int
    level: str
    family: str | None = None
    ml_probability: float | None = None
    ml_category: str | None = None
    yara_rule_count: int = 0
    signature: str | None = None
    model_version: str | None = None
    agreement: str | None = None
    analyst: str | None = None


class ThreatSnapshot(BaseModel):
    total_detections: int
    malicious: int
    suspicious: int
    benign: int
    open_alerts: int
    last_24h: int
    top_families: list[dict[str, object]] = []
