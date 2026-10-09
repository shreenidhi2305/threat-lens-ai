from datetime import datetime

from pydantic import BaseModel


class AnalyticsSummary(BaseModel):
    """Aggregated analytics for the malware analytics dashboard.

    Consolidates detection, alert, report and model data behind a single
    endpoint so the dashboard does not have to stitch together several
    module-specific calls on the frontend.
    """

    # headline totals
    total_samples: int
    classified_samples: int
    malicious: int
    suspicious: int
    benign: int
    detection_rate: float = 0.0
    last_24h: int = 0
    avg_risk_score: float = 0.0

    # breakdowns
    by_level: dict[str, int] = {}
    by_verdict: dict[str, int] = {}
    by_agreement: dict[str, int] = {}
    top_families: list[dict[str, object]] = []
    ml_only_catches: int = 0

    # cross-module context (alerts + reports)
    open_alerts: int = 0
    critical_alerts: int = 0
    reports_generated: int = 0

    # model context
    detector_version: str | None = None
    classifier_version: str | None = None

    generated_at: datetime