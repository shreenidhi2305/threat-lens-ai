"""Research workspace: malware datasets and family analysis for the Researcher role."""

from __future__ import annotations

import csv
import io
from collections import Counter, defaultdict

from app.ml.models.registry import get_classifier, get_detector
from app.modules.model_management.service import feedback_service
from app.modules.research.schemas import (
    DatasetInfo,
    FamilyDetail,
    FamilySample,
    FamilySummary,
)
from app.modules.threat_monitoring.schemas import Detection
from app.modules.threat_monitoring.service import threat_monitoring_service

_DETECTION_COLUMNS = [
    'at', 'sha256', 'filename', 'verdict', 'score', 'level', 'family', 'ml_probability',
    'ml_category', 'yara_rules', 'signature', 'engine_agreement', 'model_version',
]


def _summarise(family: str, items: list[Detection]) -> FamilySummary:
    probs = [d.ml_probability for d in items if d.ml_probability is not None]
    return FamilySummary(
        family=family,
        samples=len(items),
        malicious=sum(1 for d in items if d.verdict_label == 'malicious'),
        suspicious=sum(1 for d in items if d.verdict_label == 'suspicious'),
        avg_score=round(sum(d.score for d in items) / len(items), 1),
        avg_ml_probability=round(sum(probs) / len(probs), 4) if probs else None,
        ml_categories=dict(Counter(d.ml_category for d in items if d.ml_category)),
        signatures=sorted({d.signature for d in items if d.signature}),
        first_seen=min(d.at for d in items),
        last_seen=max(d.at for d in items),
    )


class ResearchService:
    def _by_family(self) -> dict[str, list[Detection]]:
        groups: dict[str, list[Detection]] = defaultdict(list)
        for d in threat_monitoring_service.all_detections():
            if d.family:
                groups[d.family].append(d)
        return groups

    # --- datasets ------------------------------------------------------------
    def datasets(self) -> list[DatasetInfo]:
        detector, classifier = get_detector(), get_classifier()
        det_meta = detector.meta if detector else {}
        clf_meta = classifier.meta if classifier else {}
        training_total = det_meta.get('training_samples')
        test_total = (det_meta.get('metrics') or {}).get('test_samples')

        training = DatasetInfo(
            id='training-dikedataset',
            name='DikeDataset (model training corpus)',
            kind='training',
            description='Labelled benign and malicious Windows PE files the detector and the '
                        'family classifier were trained on.',
            source='https://github.com/iosifache/DikeDataset',
            license='MIT',
            records=int(training_total or 0) + int(test_total or 0),
            stats={
                'training_samples': training_total,
                'test_samples': test_total,
                'classes': clf_meta.get('classes', []),
                'class_support': (clf_meta.get('metrics') or {}).get('support', {}),
                'model_version': detector.version if detector else None,
                'trained_at': det_meta.get('trained_at'),
                'feature_count': len(det_meta.get('feature_names', [])),
            },
            exportable=False,
            note='Raw malware is never stored by ThreatLens. Re-create the corpus with '
                 '`python -m app.ml.training.fetch_dikedataset` (streams samples into memory).',
        )

        detections = threat_monitoring_service.all_detections()
        verdicts = Counter(d.verdict_label for d in detections)
        analysed = DatasetInfo(
            id='analysed-corpus',
            name='Analysed samples (this platform)',
            kind='analysed',
            description='Every file analysed on this platform with its verdict, score, family, '
                        'ML probability and engine agreement.',
            records=len(detections),
            stats={
                'malicious': verdicts.get('malicious', 0),
                'suspicious': verdicts.get('suspicious', 0),
                'benign': verdicts.get('benign', 0),
                'families': len({d.family for d in detections if d.family}),
                'first_seen': min((d.at for d in detections), default=None),
                'last_seen': max((d.at for d in detections), default=None),
            },
            exportable=True,
            export_path='/research/datasets/analysed-corpus/export.csv',
        )

        feedback = feedback_service.list_feedback(limit=2000)
        labelled = DatasetInfo(
            id='analyst-feedback',
            name='Analyst-labelled samples',
            kind='feedback',
            description='Ground-truth labels from analysts reviewing verdicts; the retraining set.',
            records=len(feedback),
            stats={
                'confirmed_malicious': sum(1 for f in feedback if f.label == 'malicious'),
                'confirmed_benign': sum(1 for f in feedback if f.label == 'benign'),
                'model_disagreed': sum(1 for f in feedback if not f.agrees),
            },
            exportable=True,
            export_path='/research/datasets/analyst-feedback/export.csv',
        )
        return [training, analysed, labelled]

    def export_dataset(self, dataset_id: str) -> str | None:
        if dataset_id == 'analysed-corpus':
            return self._detections_csv(threat_monitoring_service.all_detections())
        if dataset_id == 'analyst-feedback':
            return feedback_service.export_csv()
        return None

    @staticmethod
    def _detections_csv(items: list[Detection]) -> str:
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(_DETECTION_COLUMNS)
        for d in items:
            writer.writerow([
                d.at.isoformat(), d.sha256, d.filename, d.verdict_label, d.score, d.level,
                d.family or '', d.ml_probability if d.ml_probability is not None else '',
                d.ml_category or '', d.yara_rule_count, d.signature or '', d.agreement or '',
                d.model_version or '',
            ])
        return buffer.getvalue()

    # --- families ------------------------------------------------------------
    def families(self) -> list[FamilySummary]:
        summaries = [_summarise(name, items) for name, items in self._by_family().items()]
        return sorted(summaries, key=lambda f: (-f.samples, f.family.lower()))

    def family(self, name: str) -> FamilyDetail | None:
        groups = self._by_family()
        key = next((k for k in groups if k.lower() == name.lower()), None)
        if key is None:
            return None
        items = sorted(groups[key], key=lambda d: d.at, reverse=True)
        base = _summarise(key, items)
        return FamilyDetail(
            **base.model_dump(),
            agreement=dict(Counter(d.agreement or 'unknown' for d in items)),
            avg_yara_rules=round(sum(d.yara_rule_count for d in items) / len(items), 2),
            recent_samples=[
                FamilySample(
                    sha256=d.sha256, filename=d.filename, verdict=d.verdict_label, score=d.score,
                    ml_probability=d.ml_probability, agreement=d.agreement, at=d.at,
                )
                for d in items[:50]
            ],
        )

    def families_csv(self) -> str:
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(['family', 'samples', 'malicious', 'suspicious', 'avg_score',
                         'avg_ml_probability', 'ml_categories', 'signatures', 'first_seen', 'last_seen'])
        for f in self.families():
            writer.writerow([
                f.family, f.samples, f.malicious, f.suspicious, f.avg_score,
                f.avg_ml_probability if f.avg_ml_probability is not None else '',
                '; '.join(f'{k}:{v}' for k, v in f.ml_categories.items()),
                '; '.join(f.signatures), f.first_seen.isoformat(), f.last_seen.isoformat(),
            ])
        return buffer.getvalue()


research_service = ResearchService()
