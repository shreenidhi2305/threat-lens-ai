from datetime import datetime
from typing import Any

from pydantic import BaseModel


class DatasetInfo(BaseModel):
    id: str
    name: str
    kind: str  # training | analysed | feedback
    description: str
    source: str | None = None
    license: str | None = None
    records: int
    stats: dict[str, Any] = {}
    exportable: bool = False
    export_path: str | None = None
    note: str | None = None


class FamilySummary(BaseModel):
    family: str
    samples: int
    malicious: int
    suspicious: int
    avg_score: float
    avg_ml_probability: float | None = None
    ml_categories: dict[str, int] = {}
    signatures: list[str] = []
    first_seen: datetime
    last_seen: datetime


class FamilySample(BaseModel):
    sha256: str
    filename: str
    verdict: str
    score: int
    ml_probability: float | None = None
    agreement: str | None = None
    at: datetime


class FamilyDetail(FamilySummary):
    agreement: dict[str, int] = {}
    avg_yara_rules: float = 0.0
    recent_samples: list[FamilySample] = []
