"""Detection logging + threat-monitoring snapshot.

In-memory store for now (process lifetime). The persistent schema is in
``supabase/migrations/003_detections_and_alerts.sql``.
"""

from __future__ import annotations

import uuid
from collections import Counter, deque
from datetime import datetime, timedelta, timezone
from app.core.config import settings
from app.modules.file_analysis.schemas import AnalysisResult
from app.modules.threat_monitoring.schemas import Detection, ThreatSnapshot
from app.db.repositories.detections import DetectionRepository

_MAX_LOG = 2000


class ThreatMonitoringService:
    def __init__(self) -> None:
        self._log: deque[Detection] = deque(maxlen=_MAX_LOG)
        self._repository = DetectionRepository()

    def record(self, result: AnalysisResult, actor: str | None = None) -> Detection:
        v = result.verdict
        ml = result.ml
        detection = Detection(
            id=str(uuid.uuid4()),
            at=datetime.now(timezone.utc),
            sha256=result.hashes.sha256,
            filename=result.object_path.split('/')[-1] or result.object_path,
            verdict_label=v.label if v else result.risk.level,
            score=v.score if v else result.risk.score,
            level=v.level if v else result.risk.level,
            family=v.family if v else None,
            ml_probability=ml.malware_probability if ml and ml.available else None,
            ml_category=ml.category if ml and ml.available else None,
            yara_rule_count=len(result.yara_matches),
            signature=result.signature_match.name if result.signature_match.matched else None,
            model_version=(ml.model_versions.get('detector') if ml and ml.available else None),
            agreement=v.agreement if v else None,
            analyst=actor,
        )
        self._log.appendleft(detection)
            

        if settings.supabase_configured:
            try:
                self._repository.create(
                    {
                        "id": detection.id,
                        "sha256": detection.sha256,
                        "filename": detection.filename,
                        "verdict_label": detection.verdict_label,
                        "score": detection.score,
                        "level": detection.level,
                        "family": detection.family,
                        "ml_probability": detection.ml_probability,
                        "ml_category": detection.ml_category,
                        "yara_rule_count": detection.yara_rule_count,
                        "signature": detection.signature,
                        "model_version": detection.model_version,
                        "agreement": detection.agreement,
                        "analyst_id": detection.analyst,
                        "created_at": detection.at,
                    }
                )
            except Exception:
                # Keep the detection in memory if Supabase fails.
                pass

        return detection
        

    def list_detections(
    self,
    limit: int = 100,
    level: str | None = None,
) -> list[Detection]:
        if settings.supabase_configured:
            try:
                rows = self._repository.list(limit=limit, level=level)

                detections = []
                for row in rows:
                    row = dict(row)

                # Map database column names to Detection model fields.
                    if "created_at" in row:
                        row["at"] = row.pop("created_at")

                    if "analyst_id" in row:
                        row["analyst"] = row.pop("analyst_id")

                    detections.append(Detection.model_validate(row))

                return detections

            except Exception:
            # Fall back to the in-memory log if Supabase is unavailable.
                pass

        items = list(self._log)

        if level:
            items = [d for d in items if d.level == level]

        return items[:limit]

    def get_snapshot(self, open_alerts: int = 0) -> ThreatSnapshot:
        items = list(self._log)
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        families = Counter(d.family for d in items if d.family and d.verdict_label == 'malicious')
        return ThreatSnapshot(
            total_detections=len(items),
            malicious=sum(1 for d in items if d.verdict_label == 'malicious'),
            suspicious=sum(1 for d in items if d.verdict_label == 'suspicious'),
            benign=sum(1 for d in items if d.verdict_label == 'benign'),
            open_alerts=open_alerts,
            last_24h=sum(1 for d in items if d.at >= cutoff),
            top_families=[{'family': f, 'count': c} for f, c in families.most_common(6)],
        )


threat_monitoring_service = ThreatMonitoringService()
