"""Fetch DikeDataset and build the training feature cache.

Streams each sample straight from GitHub into memory, runs the Milestone 1
static-analysis pipeline + the unified feature extractor, and writes only the
resulting feature matrix to ``.cache/``. **Raw malware is never written to
disk** (keeps local antivirus out of the way and is much faster than a full
clone).

    python -m app.ml.training.fetch_dikedataset --malware 2600

Set GITHUB_TOKEN to raise the raw.githubusercontent rate limit if needed.
"""

from __future__ import annotations

import argparse
import csv
import io
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

import numpy as np
import requests

from app.ml.features.extractor import FEATURE_NAMES, extract_features
from app.ml.training.dataset import FAMILY_COLUMNS
from app.ml.training.train import CACHE_DIR

RAW = 'https://raw.githubusercontent.com/iosifache/DikeDataset/main'
_SESSION = requests.Session()
if os.environ.get('GITHUB_TOKEN'):
    _SESSION.headers['Authorization'] = f"token {os.environ['GITHUB_TOKEN']}"


def _category(row: dict[str, str]) -> str:
    scores = {c: float(row.get(c, 0) or 0) for c in FAMILY_COLUMNS}
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else 'generic'


def _load_labels() -> list[tuple[str, str, str]]:
    """Return [(kind, sha256, category)] balanced across malware families."""
    out_benign: list[tuple[str, str, str]] = []
    by_cat: dict[str, list[str]] = {c: [] for c in FAMILY_COLUMNS}
    for kind in ('benign', 'malware'):
        text = _SESSION.get(f'{RAW}/labels/{kind}.csv', timeout=30).text
        for row in csv.DictReader(io.StringIO(text)):
            h = (row.get('hash') or '').strip()
            if not h:
                continue
            if kind == 'benign':
                out_benign.append(('benign', h, 'benign'))
            else:
                by_cat[_category(row)].append(h)
    return out_benign, by_cat


def _pick(malware_budget: int) -> list[tuple[str, str, str]]:
    benign, by_cat = _load_labels()
    malware: list[tuple[str, str, str]] = []
    i = 0
    cats = FAMILY_COLUMNS
    while len(malware) < malware_budget and any(by_cat.values()):
        c = cats[i % len(cats)]
        if by_cat[c]:
            malware.append(('malware', by_cat[c].pop(), c))
        i += 1
    dist: dict[str, int] = {}
    for _, _, c in malware:
        dist[c] = dist.get(c, 0) + 1
    print(f'benign={len(benign)}  malware={len(malware)}  family dist={dist}')
    return benign + malware


def _fetch_one(item: tuple[str, str, str]):
    kind, h, cat = item
    for ext in ('.exe', '.ole', ''):
        r = _SESSION.get(f'{RAW}/files/{kind}/{h}{ext}', timeout=45)
        if r.status_code == 200 and r.content:
            data = r.content
            break
    else:
        return None
    try:
        from app.modules.file_analysis.service import file_analysis_service

        analysis = file_analysis_service.analyze_static_file(h, data).model_dump()
    except Exception:  # noqa: BLE001
        analysis = {}
    return extract_features(data, analysis), (0 if kind == 'benign' else 1), cat


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--malware', type=int, default=2600)
    ap.add_argument('--workers', type=int, default=16)
    ap.add_argument('--out', default=None)
    args = ap.parse_args()

    items = _pick(args.malware)
    X, y_det, y_cat = [], [], []
    fails = 0
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(_fetch_one, it) for it in items]
        for n, fut in enumerate(as_completed(futs), 1):
            res = fut.result()
            if res is None:
                fails += 1
            else:
                vec, yd, yc = res
                X.append(vec)
                y_det.append(yd)
                y_cat.append(yc)
            if n % 200 == 0:
                print(f'  {n}/{len(items)}  ok={len(X)} fail={fails}', flush=True)

    if not X:
        sys.exit('Fetched nothing. Check network / GitHub rate limit (set GITHUB_TOKEN).')

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    out = CACHE_DIR / (args.out or f'dike_{len(X)}_{len(FEATURE_NAMES)}.npz')
    np.savez_compressed(
        out,
        X=np.vstack(X).astype(np.float32),
        y_det=np.array(y_det, dtype=np.int8),
        y_cat=np.array(y_cat, dtype=object),
    )
    print(f'\nWrote {out}  ({len(X)} samples, {len(FEATURE_NAMES)} features, {fails} failed)')
    print(f'Train with:  python -m app.ml.training.train --features-npz {out}')


if __name__ == '__main__':
    main()
