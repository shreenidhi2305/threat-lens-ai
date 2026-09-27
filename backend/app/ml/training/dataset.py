"""Load the DikeDataset (https://github.com/iosifache/DikeDataset, MIT) for training.

Expected layout under ``--dataset-dir``:

    files/benign/<sha256>       raw benign PE / OLE files
    files/malware/<sha256>      raw malicious files
    labels/benign.csv           columns: type,hash,malice,<family cols...>
    labels/malware.csv          same schema; family columns hold soft scores
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

# DikeDataset family columns -> the category label we train on.
FAMILY_COLUMNS = [
    'generic', 'trojan', 'ransomware', 'worm', 'backdoor',
    'spyware', 'rootkit', 'encrypter', 'downloader',
]
CATEGORIES = FAMILY_COLUMNS  # keep the same names; "generic" is the catch-all


@dataclass(frozen=True)
class Sample:
    path: Path
    sha256: str
    is_malware: bool
    category: str | None  # None for benign


def _category_from_row(row: dict[str, str]) -> str:
    scores = {col: float(row.get(col, 0) or 0) for col in FAMILY_COLUMNS}
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else 'generic'


def load_samples(dataset_dir: str | Path, limit: int | None = None) -> list[Sample]:
    root = Path(dataset_dir)
    samples: list[Sample] = []

    for kind, is_mal in (('benign', False), ('malware', True)):
        label_csv = root / 'labels' / f'{kind}.csv'
        files_dir = root / 'files' / kind
        if not label_csv.is_file():
            continue
        with label_csv.open(newline='', encoding='utf-8') as fh:
            for row in csv.DictReader(fh):
                sha = (row.get('hash') or '').strip()
                if not sha:
                    continue
                fpath = files_dir / sha
                if not fpath.is_file():
                    continue
                samples.append(
                    Sample(
                        path=fpath,
                        sha256=sha,
                        is_malware=is_mal,
                        category=_category_from_row(row) if is_mal else None,
                    )
                )

    samples.sort(key=lambda s: s.sha256)
    if limit is not None:
        # keep class balance when truncating
        mal = [s for s in samples if s.is_malware][: limit // 2]
        ben = [s for s in samples if not s.is_malware][: limit - len(mal)]
        samples = sorted(mal + ben, key=lambda s: s.sha256)
    return samples
