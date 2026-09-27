"""Hash-based (signature) malware detection.

Looks the sample's SHA-256 up against a local signature set
(``file_analysis/data/signatures.json``). This is the fast, zero-false-positive
first pass; behavioural/ML classification comes later in the pipeline.
"""

import functools
import json
from pathlib import Path

_SIGNATURES_FILE = Path(__file__).resolve().parent.parent / 'data' / 'signatures.json'


@functools.lru_cache(maxsize=1)
def _signatures() -> dict[str, dict]:
    raw = json.loads(_SIGNATURES_FILE.read_text(encoding='utf-8'))
    return {entry['sha256'].lower(): entry for entry in raw.get('signatures', [])}


def match_signature(sha256: str) -> dict:
    entry = _signatures().get(sha256.lower())
    if entry is None:
        return {'matched': False, 'name': None, 'type': None, 'severity': None}
    return {
        'matched': True,
        'name': entry['name'],
        'type': entry.get('type'),
        'severity': entry.get('severity'),
    }
