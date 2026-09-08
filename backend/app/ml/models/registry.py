"""Model registry: loads the trained LightGBM artifacts and their metadata.

Artifacts live in ``ml/models/artifacts/`` and are produced by
``ml/training/train.py``:

    detector.txt   / detector.json     - binary malicious/benign LightGBM booster
    classifier.txt / classifier.json   - multiclass malware-category LightGBM booster

Each ``.json`` sidecar holds: ``version``, ``trained_at``, ``feature_names``,
``classes`` (classifier only), ``threshold`` (detector only), ``metrics``.
"""

from __future__ import annotations

import functools
import json
from pathlib import Path
from typing import Any

try:
    import lightgbm as lgb
except ImportError:  # pragma: no cover
    lgb = None  # type: ignore

ARTIFACTS_DIR = Path(__file__).resolve().parent / 'artifacts'


class LoadedModel:
    def __init__(self, booster: Any, meta: dict[str, Any]):
        self.booster = booster
        self.meta = meta

    @property
    def version(self) -> str:
        return str(self.meta.get('version', 'unknown'))

    @property
    def feature_names(self) -> list[str]:
        return list(self.meta.get('feature_names', []))


def _load(stem: str) -> LoadedModel | None:
    model_path = ARTIFACTS_DIR / f'{stem}.txt'
    meta_path = ARTIFACTS_DIR / f'{stem}.json'
    if lgb is None or not model_path.is_file() or not meta_path.is_file():
        return None
    booster = lgb.Booster(model_file=str(model_path))
    meta = json.loads(meta_path.read_text(encoding='utf-8'))
    return LoadedModel(booster, meta)


@functools.lru_cache(maxsize=1)
def get_detector() -> LoadedModel | None:
    return _load('detector')


@functools.lru_cache(maxsize=1)
def get_classifier() -> LoadedModel | None:
    return _load('classifier')


def registry_status() -> dict[str, Any]:
    det, clf = get_detector(), get_classifier()
    return {
        'detector': None if det is None else {
            'version': det.version,
            'trained_at': det.meta.get('trained_at'),
            'metrics': det.meta.get('metrics', {}),
            'threshold': det.meta.get('threshold'),
        },
        'classifier': None if clf is None else {
            'version': clf.version,
            'trained_at': clf.meta.get('trained_at'),
            'classes': clf.meta.get('classes', []),
            'metrics': clf.meta.get('metrics', {}),
        },
    }


def reload_models() -> None:
    get_detector.cache_clear()
    get_classifier.cache_clear()
