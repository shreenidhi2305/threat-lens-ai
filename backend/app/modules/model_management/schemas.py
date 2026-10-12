from datetime import datetime

from pydantic import BaseModel, Field


class FeedbackRequest(BaseModel):
    sha256: str = Field(min_length=64, max_length=64, pattern='^[0-9a-fA-F]{64}$')
    label: str = Field(pattern='^(malicious|benign)$')
    note: str | None = Field(default=None, max_length=300)


class FeedbackRecord(BaseModel):
    id: str
    at: datetime
    sha256: str
    filename: str | None = None
    label: str  # the analyst's ground truth: malicious | benign
    model_verdict: str | None = None  # what the platform concluded: malicious | suspicious | benign
    model_score: int | None = None
    ml_probability: float | None = None
    ml_applicable: bool | None = None  # the ML detector only scores PE files
    note: str | None = None
    actor: str | None = None
    agrees: bool = True


class ConfusionCounts(BaseModel):
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    precision: float | None = None
    recall: float | None = None
    accuracy: float | None = None


class FeedbackSummary(BaseModel):
    total: int
    confirmed_malicious: int
    confirmed_benign: int
    agreement_rate: float | None = None
    fused_verdict: ConfusionCounts
    ml_detector: ConfusionCounts
    retrain_recommended: bool
    retrain_reason: str
    min_samples: int
