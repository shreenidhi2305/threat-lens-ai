"""Analyst feedback loop: the "continuous learning & updates" part of the ML engine.

Analysts confirm or correct a verdict ("this was actually benign" / "this really is
malware"). That ground truth is stored per sample and compared with what the platform
concluded, which gives a live precision/recall estimate for the deployed model and a
labelled set to retrain from. When enough corrections show the model drifting, the
administrator is told retraining is recommended. Retraining itself is an offline step
(``python -m app.ml.training.train``) followed by a hot model reload from the admin page.
"""

from __future__ import annotations

import csv
import io
import logging
import threading
import uuid
from datetime import datetime, timezone

from app.core.config import settings
from app.db.repositories.feedback import FeedbackRepository
from app.ml.models.registry import get_detector
from app.modules.model_management.schemas import (
    ConfusionCounts,
    FeedbackRecord,
    FeedbackSummary,
)
from app.modules.threat_monitoring.service import threat_monitoring_service

logger = logging.getLogger(__name__)

MIN_SAMPLES_FOR_DRIFT = 25
DRIFT_ERROR_RATE = 0.10


def _confusion(pairs: list[tuple[bool, bool]]) -> ConfusionCounts:
    """``pairs`` are (predicted_malicious, actually_malicious)."""
    tp = sum(1 for p, a in pairs if p and a)
    fp = sum(1 for p, a in pairs if p and not a)
    tn = sum(1 for p, a in pairs if not p and not a)
    fn = sum(1 for p, a in pairs if not p and a)
    total = len(pairs)
    return ConfusionCounts(
        tp=tp, fp=fp, tn=tn, fn=fn,
        precision=round(tp / (tp + fp), 4) if (tp + fp) else None,
        recall=round(tp / (tp + fn), 4) if (tp + fn) else None,
        accuracy=round((tp + tn) / total, 4) if total else None,
    )


class FeedbackService:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_sha: dict[str, FeedbackRecord] = {}
        self._repository = FeedbackRepository()

    def submit(self, sha256: str, label: str, note: str | None, actor: str | None) -> FeedbackRecord:
        sha256 = sha256.lower()
        detection = next((d for d in threat_monitoring_service.all_detections() if d.sha256 == sha256), None)
        if detection is None:
            raise LookupError('No analysed sample with that hash')
        predicted_malicious = detection.verdict_label == 'malicious'
        record = FeedbackRecord(
            id=str(uuid.uuid4()),
            at=datetime.now(timezone.utc),
            sha256=sha256,
            filename=detection.filename,
            label=label,
            model_verdict=detection.verdict_label,
            model_score=detection.score,
            ml_probability=detection.ml_probability,
            ml_applicable=getattr(detection, 'ml_applicable', None),
            note=note,
            actor=actor,
            agrees=(predicted_malicious == (label == 'malicious')),
        )
        with self._lock:
            self._by_sha[sha256] = record  # the latest correction for a sample wins
        self._persist(record)
        return record

    def _persist(self, record: FeedbackRecord) -> None:
        if not settings.supabase_configured:
            return
        try:
            self._repository.upsert({
                'id': record.id,
                'sha256': record.sha256,
                'filename': record.filename,
                'label': record.label,
                'model_verdict': record.model_verdict,
                'model_score': record.model_score,
                'ml_probability': record.ml_probability,
                'ml_applicable': record.ml_applicable,
                'note': record.note,
                'actor': record.actor,
                'agrees': record.agrees,
                'created_at': record.at.isoformat(),
            })
        except Exception:  # noqa: BLE001
            logger.warning('Could not persist feedback for %s; kept in memory', record.sha256)

    def _all(self) -> list[FeedbackRecord]:
        items = {}
        if settings.supabase_configured:
            try:
                for row in self._repository.list():
                    row = dict(row)
                    row['at'] = row.pop('created_at', None)
                    rec = FeedbackRecord.model_validate(
                        {k: v for k, v in row.items() if k in FeedbackRecord.model_fields}
                    )
                    items[rec.sha256] = rec
            except Exception:  # noqa: BLE001
                pass
        with self._lock:
            for sha, rec in self._by_sha.items():
                if sha not in items or rec.at >= items[sha].at:
                    items[sha] = rec
        return sorted(items.values(), key=lambda r: r.at, reverse=True)

    def list_feedback(self, limit: int = 200) -> list[FeedbackRecord]:
        return self._all()[:limit]

    def for_sha(self, sha256: str) -> FeedbackRecord | None:
        return next((r for r in self._all() if r.sha256 == sha256.lower()), None)

    def summary(self) -> FeedbackSummary:
        items = self._all()
        actual = [r.label == 'malicious' for r in items]
        fused = _confusion([(r.model_verdict == 'malicious', a) for r, a in zip(items, actual)])

        detector = get_detector()
        threshold = float(detector.meta.get('threshold', 0.5)) if detector else 0.5
        # only files the detector actually scores (PE files) say anything about its accuracy
        with_ml = [
            (r, a) for r, a in zip(items, actual)
            if r.ml_probability is not None and r.ml_applicable
        ]
        ml = _confusion([(r.ml_probability >= threshold, a) for r, a in with_ml])

        total = len(items)
        errors = fused.fp + fused.fn
        error_rate = errors / total if total else 0.0
        if total < MIN_SAMPLES_FOR_DRIFT:
            recommended, reason = False, (
                f'{total} of {MIN_SAMPLES_FOR_DRIFT} corrections collected before drift can be judged.'
            )
        elif error_rate >= DRIFT_ERROR_RATE:
            recommended, reason = True, (
                f'{errors} of {total} analyst-reviewed verdicts were wrong ({error_rate:.0%}); '
                'retrain from the labelled export.'
            )
        else:
            recommended, reason = False, (
                f'Verdicts match analyst review ({1 - error_rate:.0%} of {total}); no retraining needed.'
            )
        return FeedbackSummary(
            total=total,
            confirmed_malicious=sum(actual),
            confirmed_benign=total - sum(actual),
            agreement_rate=round(sum(1 for r in items if r.agrees) / total, 4) if total else None,
            fused_verdict=fused,
            ml_detector=ml,
            retrain_recommended=recommended,
            retrain_reason=reason,
            min_samples=MIN_SAMPLES_FOR_DRIFT,
        )

    def export_csv(self) -> str:
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(['sha256', 'filename', 'analyst_label', 'model_verdict', 'model_score',
                         'ml_probability', 'agrees', 'note', 'analyst', 'at'])
        for r in self._all():
            writer.writerow([r.sha256, r.filename or '', r.label, r.model_verdict or '',
                             r.model_score if r.model_score is not None else '',
                             r.ml_probability if r.ml_probability is not None else '',
                             r.agrees, r.note or '', r.actor or '', r.at.isoformat()])
        return buffer.getvalue()


feedback_service = FeedbackService()
