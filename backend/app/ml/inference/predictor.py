"""ML inference: run the trained models over a sample's feature vector.

Called by the malware-classification service after static analysis. Produces a
malicious probability, a malware category with confidence, and the model
versions used.
"""

from __future__ import annotations

from typing import Any

import numpy as np

from app.ml.features.extractor import FEATURE_NAMES, extract_features
from app.ml.models.registry import get_classifier, get_detector

_DEFAULT_THRESHOLD = 0.5


class Predictor:
    """Compatibility adapter for direct feature-based classification requests.

    Stored-sample scans use ``predict`` below and the model registry. This
    adapter remains temporary until callers exclusively use the full pipeline.
    """

    def predict(self, model_name: str, features: Any) -> dict[str, Any]:
        risk_score = int(features.get('risk_score', 0)) if isinstance(features, dict) else 0
        signature_type = features.get('signature_type') if isinstance(features, dict) else None
        if signature_type:
            predicted_class = str(signature_type)
        elif risk_score >= 80:
            predicted_class = 'Ransomware'
        elif risk_score >= 60:
            predicted_class = 'Trojan'
        elif risk_score >= 20:
            predicted_class = 'Spyware'
        else:
            predicted_class = 'Benign'
        confidence = round(min(0.99, max(0.55, 0.55 + abs(risk_score - 50) / 100)), 2)
        if predicted_class == 'Benign':
            confidence = round(max(confidence, 0.90), 2)
        return {
            'model_name': model_name,
            'source': 'mock',
            'predicted_class': predicted_class,
            'confidence': confidence,
        }


class MalwarePrediction:
    def __init__(self, data: dict[str, Any]):
        self.__dict__.update(data)
        self._data = data

    def as_dict(self) -> dict[str, Any]:
        return self._data


def _align(vec: np.ndarray, model_feature_names: list[str]) -> np.ndarray:
    """Reorder / pad the vector to the feature order the model was trained on."""
    if not model_feature_names or model_feature_names == FEATURE_NAMES:
        return vec.reshape(1, -1)
    index = {name: i for i, name in enumerate(FEATURE_NAMES)}
    aligned = np.zeros(len(model_feature_names), dtype=np.float32)
    for j, name in enumerate(model_feature_names):
        i = index.get(name)
        if i is not None:
            aligned[j] = vec[i]
    return aligned.reshape(1, -1)


def predict(data: bytes, analysis: dict | None = None) -> dict[str, Any]:
    detector = get_detector()
    classifier = get_classifier()

    if detector is None:
        return {
            'available': False,
            'reason': 'detection model not loaded',
            'applicable': False,
            'malicious': None,
            'malware_probability': None,
            'category': None,
            'category_confidence': None,
            'model_versions': {},
        }

    # The models are trained on Windows PE files. On other file types they still
    # run, but the rule engine is the authoritative signal (see fusion).
    applicable = data[:2] == b'MZ'
    features = extract_features(data, analysis)

    det_x = _align(features, detector.feature_names)
    prob = float(detector.booster.predict(det_x)[0])
    threshold = float(detector.meta.get('threshold', _DEFAULT_THRESHOLD))
    malicious = prob >= threshold

    category: str | None = None
    category_confidence: float | None = None
    top_categories: list[dict[str, Any]] = []
    if classifier is not None:
        clf_x = _align(features, classifier.feature_names)
        probs = np.asarray(classifier.booster.predict(clf_x)[0], dtype=float)
        classes = classifier.meta.get('classes', [])
        order = np.argsort(probs)[::-1]
        top_categories = [
            {'category': classes[i], 'probability': round(float(probs[i]), 4)}
            for i in order[:3]
            if i < len(classes)
        ]
        if top_categories:
            category = top_categories[0]['category']
            category_confidence = top_categories[0]['probability']

    return {
        'available': True,
        'applicable': applicable,
        'malicious': malicious,
        'malware_probability': round(prob, 4),
        'category': (category if malicious else 'benign'),
        'category_confidence': category_confidence,
        'top_categories': top_categories,
        'model_versions': {
            'detector': detector.version,
            'classifier': classifier.version if classifier else None,
        },
    }
