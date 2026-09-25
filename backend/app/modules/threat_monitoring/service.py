"""Detection logging + threat-monitoring snapshot.

Persisted to Supabase (via ``DetectionRepository``) when configured, with an
in-memory ring buffer as both the local-dev store and the fallback if Supabase
is unreachable. The persistent schema is in
``supabase/migrations/003_detections_and_alerts.sql``.
"""

from __future__ import annotations

import uuid
from collections import Counter, deque
from datetime import datetime, timedelta, timezone

from app.core.config import settings
from app.db.repositories.detections import DetectionRepository
from app.modules.file_analysis.schemas import AnalysisResult
from app.modules.threat_monitoring.schemas import Detection, ThreatSnapshot

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
        self._persist(detection)
        return detection

    def _persist(self, detection: Detection) -> None:
        if not settings.supabase_configured:
            return
        try:
            self._repository.create({
                'id': detection.id,
                'sha256': detection.sha256,
                'filename': detection.filename,
                'verdict_label': detection.verdict_label,
                'score': detection.score,
                'level': detection.level,
                'family': detection.family,
                'ml_probability': detection.ml_probability,
                'ml_category': detection.ml_category,
                'yara_rule_count': detection.yara_rule_count,
                'signature': detection.signature,
                'model_version': detection.model_version,
                'agreement': detection.agreement,
                'analyst_id': detection.analyst,
                'created_at': detection.at,
            })
        except Exception:
            # Keep the detection in memory if Supabase is unavailable.
            pass

    def all_detections(self) -> list[Detection]:
        """Public accessor for the full detection set (used by the analytics module)."""
        return self._all()

    def _all(self) -> list[Detection]:
        """The current dataset: Supabase-backed when configured, else in-memory."""
        if settings.supabase_configured:
            try:
                rows = self._repository.list(limit=_MAX_LOG)
                items = []
                for row in rows:
                    row = dict(row)
                    if 'created_at' in row:
                        row['at'] = row.pop('created_at')
                    if 'analyst_id' in row:
                        row['analyst'] = row.pop('analyst_id')
                    items.append(Detection.model_validate(row))
                return items
            except Exception:
                pass  # fall back to the in-memory log below
        return list(self._log)

    def _apply_filters(
        self,
        items: list[Detection],
        level: str | None = None,
        verdict: str | None = None,
        family: str | None = None,
        q: str | None = None,
    ) -> list[Detection]:
        if level:
            items = [d for d in items if d.level == level]
        if verdict:
            items = [d for d in items if d.verdict_label == verdict]
        if family:
            items = [d for d in items if (d.family or '').lower() == family.lower()]
        if q:
            needle = q.strip().lower()
            if needle:
                items = [
                    d
                    for d in items
                    if needle in d.filename.lower()
                    or needle in d.sha256.lower()
                    or needle in (d.family or '').lower()
                    or needle in (d.signature or '').lower()
                ]
        return items

    def list_detections(
        self,
        limit: int = 100,
        level: str | None = None,
        verdict: str | None = None,
        family: str | None = None,
        q: str | None = None,
    ) -> list[Detection]:
        items = self._apply_filters(self._all(), level=level, verdict=verdict, family=family, q=q)
        return items[:limit]

    def distinct_families(self) -> list[str]:
        return sorted({d.family for d in self._all() if d.family})

    def get_snapshot(self, open_alerts: int = 0) -> ThreatSnapshot:
        items = self._all()
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

    def get_stats(self, open_alerts: int = 0) -> dict:
        items = self._all()
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        total = len(items)
        malicious = sum(1 for d in items if d.verdict_label == 'malicious')
        suspicious = sum(1 for d in items if d.verdict_label == 'suspicious')
        benign = sum(1 for d in items if d.verdict_label == 'benign')
        families = Counter(d.family for d in items if d.family)
        mal_families = Counter(
            d.family for d in items if d.family and d.verdict_label == 'malicious'
        )
        return {
            'total_detections': total,
            'malicious': malicious,
            'suspicious': suspicious,
            'benign': benign,
            'open_alerts': open_alerts,
            'last_24h': sum(1 for d in items if d.at >= cutoff),
            'detection_rate': round((malicious + suspicious) / total, 4) if total else 0.0,
            'by_level': dict(Counter(d.level for d in items)),
            'by_verdict': dict(Counter(d.verdict_label for d in items)),
            'by_agreement': dict(Counter(d.agreement or 'unknown' for d in items)),
            'by_family': [{'family': f, 'count': c} for f, c in families.most_common(10)],
            'ml_only_catches': sum(1 for d in items if d.agreement == 'ml-only'),
            'top_families': [{'family': f, 'count': c} for f, c in mal_families.most_common(6)],
        }

    def get_timeline(self, window: str = '24h') -> list[dict]:
        """Bucket detections for the activity chart.

        window: '24h' -> 24 x 1-hour buckets, '7d' -> 7 x 1-day buckets,
        '30d' -> 30 x 1-day buckets.
        """
        now = datetime.now(timezone.utc)
        if window == '7d':
            n, step = 7, timedelta(days=1)
        elif window == '30d':
            n, step = 30, timedelta(days=1)
        else:
            window = '24h'
            n, step = 24, timedelta(hours=1)

        # Align bucket starts to the hour / day so charts look stable.
        if step >= timedelta(days=1):
            base = now.replace(hour=0, minute=0, second=0, microsecond=0)
        else:
            base = now.replace(minute=0, second=0, microsecond=0)
        starts = [base - (n - 1 - i) * step for i in range(n)]

        buckets = [
            {
                'bucket': s,
                'label': s.strftime('%H:00') if step < timedelta(days=1) else s.strftime('%m-%d'),
                'total': 0,
                'malicious': 0,
                'suspicious': 0,
                'benign': 0,
            }
            for s in starts
        ]
        for d in self._all():
            at = d.at if d.at.tzinfo else d.at.replace(tzinfo=timezone.utc)
            if at < starts[0]:
                continue
            idx = int((at - starts[0]) // step)
            if 0 <= idx < n:
                buckets[idx]['total'] += 1
                if d.verdict_label in ('malicious', 'suspicious', 'benign'):
                    buckets[idx][d.verdict_label] += 1
        return buckets


threat_monitoring_service = ThreatMonitoringService()