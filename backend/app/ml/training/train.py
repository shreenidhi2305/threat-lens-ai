"""Train the detection + classification models.

    python -m app.ml.training.train --dataset-dir /path/to/DikeDataset

Steps: extract the unified feature vector over every sample (cached to an
``.npz``), train a binary LightGBM detector and a multiclass LightGBM category
classifier, evaluate on a held-out split, and write the artifacts the model
registry loads.

Run from the ``backend/`` directory (needs ``app`` on the path).
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

import numpy as np

from app.ml.features.extractor import FEATURE_NAMES, extract_features
from app.ml.training.dataset import CATEGORIES, load_samples

ARTIFACTS_DIR = Path(__file__).resolve().parents[1] / 'models' / 'artifacts'
CACHE_DIR = Path(__file__).resolve().parent / '.cache'


def _analyze(name: str, data: bytes) -> dict:
    """Run the Milestone 1 static-analysis pipeline to get the rule signals."""
    from app.modules.file_analysis.service import file_analysis_service

    try:
        return file_analysis_service.analyze_static_file(name, data).model_dump()
    except Exception:  # noqa: BLE001 - a broken sample should not stop training
        return {}


def build_features(dataset_dir: str, limit: int | None, cache: bool) -> dict:
    samples = load_samples(dataset_dir, limit=limit)
    if not samples:
        sys.exit(f'No samples found under {dataset_dir!r}. Check the layout (files/, labels/).')

    key = f'{Path(dataset_dir).name}_{limit or "all"}_{len(FEATURE_NAMES)}'
    cache_path = CACHE_DIR / f'{key}.npz'
    if cache and cache_path.is_file():
        print(f'Loading cached features from {cache_path}')
        d = np.load(cache_path, allow_pickle=True)
        return {k: d[k] for k in d.files}

    print(f'Extracting features for {len(samples)} samples...')
    X, y_det, y_cat = [], [], []
    for i, s in enumerate(samples, 1):
        if i % 250 == 0:
            print(f'  {i}/{len(samples)}')
        try:
            data = s.path.read_bytes()
        except OSError:
            continue
        analysis = _analyze(s.sha256, data)
        X.append(extract_features(data, analysis))
        y_det.append(1 if s.is_malware else 0)
        y_cat.append(s.category or 'benign')

    out = {
        'X': np.vstack(X).astype(np.float32),
        'y_det': np.array(y_det, dtype=np.int8),
        'y_cat': np.array(y_cat, dtype=object),
    }
    if cache:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        np.savez_compressed(cache_path, **out)
        print(f'Cached features to {cache_path}')
    return out


def _split(n: int, seed: int, test_frac: float) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    idx = rng.permutation(n)
    cut = int(n * (1 - test_frac))
    return idx[:cut], idx[cut:]


def train_detector(X, y, feat_names, seed) -> dict:
    import lightgbm as lgb
    from sklearn.metrics import (
        confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score,
    )

    tr, te = _split(len(y), seed, 0.2)
    dtrain = lgb.Dataset(X[tr], label=y[tr], feature_name=feat_names)
    params = {
        'objective': 'binary', 'metric': 'auc', 'learning_rate': 0.05,
        'num_leaves': 128, 'feature_fraction': 0.8, 'bagging_fraction': 0.8,
        'bagging_freq': 1, 'min_data_in_leaf': 20, 'verbose': -1, 'seed': seed,
    }
    booster = lgb.train(params, dtrain, num_boost_round=400)

    p = booster.predict(X[te])
    yt = y[te]
    # threshold for ~1% false-positive rate on benign
    ben_scores = np.sort(p[yt == 0])
    threshold = float(ben_scores[int(len(ben_scores) * 0.99)]) if len(ben_scores) else 0.5
    threshold = min(max(threshold, 0.5), 0.95)
    pred = (p >= threshold).astype(int)

    tn, fp, fn, tp = confusion_matrix(yt, pred, labels=[0, 1]).ravel()
    metrics = {
        'roc_auc': round(float(roc_auc_score(yt, p)), 4),
        'precision': round(float(precision_score(yt, pred, zero_division=0)), 4),
        'recall': round(float(recall_score(yt, pred, zero_division=0)), 4),
        'f1': round(float(f1_score(yt, pred, zero_division=0)), 4),
        'false_positive_rate': round(float(fp / (fp + tn)) if (fp + tn) else 0.0, 4),
        'confusion_matrix': {'tn': int(tn), 'fp': int(fp), 'fn': int(fn), 'tp': int(tp)},
        'test_samples': int(len(yt)),
    }
    return {'booster': booster, 'threshold': threshold, 'metrics': metrics}


def train_classifier(X, y_cat, feat_names, seed) -> dict:
    import lightgbm as lgb
    from sklearn.metrics import classification_report

    mask = y_cat != 'benign'
    Xc, yc_raw = X[mask], y_cat[mask]
    classes = [c for c in CATEGORIES if c in set(yc_raw)]
    cls_index = {c: i for i, c in enumerate(classes)}
    yc = np.array([cls_index[c] for c in yc_raw], dtype=int)

    tr, te = _split(len(yc), seed, 0.2)
    dtrain = lgb.Dataset(Xc[tr], label=yc[tr], feature_name=feat_names)
    params = {
        'objective': 'multiclass', 'num_class': len(classes), 'metric': 'multi_logloss',
        'learning_rate': 0.05, 'num_leaves': 128, 'feature_fraction': 0.8,
        'bagging_fraction': 0.8, 'bagging_freq': 1, 'min_data_in_leaf': 10,
        'verbose': -1, 'seed': seed,
    }
    booster = lgb.train(params, dtrain, num_boost_round=400)

    pred = np.argmax(booster.predict(Xc[te]), axis=1)
    report = classification_report(
        yc[te], pred, labels=list(range(len(classes))), target_names=classes,
        output_dict=True, zero_division=0,
    )
    metrics = {
        'accuracy': round(float(report['accuracy']), 4),
        'macro_f1': round(float(report['macro avg']['f1-score']), 4),
        'per_class_f1': {c: round(float(report[c]['f1-score']), 4) for c in classes},
        'support': {c: int(report[c]['support']) for c in classes},
        'test_samples': int(len(te)),
    }
    return {'booster': booster, 'classes': classes, 'metrics': metrics}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--dataset-dir', help='DikeDataset dir (files/, labels/) - extract features locally')
    ap.add_argument('--features-npz', help='pre-built feature cache from fetch_dikedataset.py')
    ap.add_argument('--limit', type=int, default=None, help='cap #samples (balanced) for a quick run')
    ap.add_argument('--seed', type=int, default=42)
    ap.add_argument('--no-cache', action='store_true')
    ap.add_argument('--version', default=None, help='model version label (default: date)')
    args = ap.parse_args()

    if not args.dataset_dir and not args.features_npz:
        ap.error('pass either --dataset-dir or --features-npz')

    version = args.version or dt.date.today().isoformat()
    if args.features_npz:
        d = np.load(args.features_npz, allow_pickle=True)
        data = {k: d[k] for k in d.files}
    else:
        data = build_features(args.dataset_dir, args.limit, cache=not args.no_cache)
    X, y_det, y_cat = data['X'], data['y_det'], data['y_cat']
    print(f'Feature matrix: {X.shape}  malware={int(y_det.sum())}  benign={int((y_det == 0).sum())}')

    print('\nTraining detector...')
    det = train_detector(X, y_det, FEATURE_NAMES, args.seed)
    print(json.dumps(det['metrics'], indent=2))

    print('\nTraining category classifier...')
    clf = train_classifier(X, y_cat, FEATURE_NAMES, args.seed)
    print(json.dumps(clf['metrics'], indent=2))

    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    trained_at = dt.datetime.now(dt.timezone.utc).isoformat()
    source = Path(args.dataset_dir).name if args.dataset_dir else Path(args.features_npz).name

    det['booster'].save_model(str(ARTIFACTS_DIR / 'detector.txt'))
    (ARTIFACTS_DIR / 'detector.json').write_text(json.dumps({
        'version': version, 'trained_at': trained_at, 'model_type': 'lightgbm.binary',
        'feature_names': FEATURE_NAMES, 'threshold': det['threshold'],
        'metrics': det['metrics'], 'training_samples': int(len(y_det)),
        'dataset': source,
    }, indent=2), encoding='utf-8')

    clf['booster'].save_model(str(ARTIFACTS_DIR / 'classifier.txt'))
    (ARTIFACTS_DIR / 'classifier.json').write_text(json.dumps({
        'version': version, 'trained_at': trained_at, 'model_type': 'lightgbm.multiclass',
        'feature_names': FEATURE_NAMES, 'classes': clf['classes'],
        'metrics': clf['metrics'], 'dataset': source,
    }, indent=2), encoding='utf-8')

    print(f'\nArtifacts written to {ARTIFACTS_DIR}')


if __name__ == '__main__':
    main()
