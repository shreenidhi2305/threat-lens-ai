"""YARA rule matching for static analysis.

Rules live in ``file_analysis/rules/*.yar`` and are compiled once per process.
If ``yara-python`` is not installed the analyzer degrades gracefully: it returns
no matches and reports ``available = False`` so callers/UI can say so rather than
silently claiming the file is clean.
"""

import functools
from pathlib import Path

try:
    import yara  # type: ignore

    _YARA_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on the environment
    yara = None  # type: ignore
    _YARA_AVAILABLE = False

_RULES_DIR = Path(__file__).resolve().parent.parent / 'rules'
_MAX_STRING_MATCHES = 20


def yara_available() -> bool:
    return _YARA_AVAILABLE


@functools.lru_cache(maxsize=1)
def _compiled_rules():
    if not _YARA_AVAILABLE:
        return None
    filepaths = {p.stem: str(p) for p in sorted(_RULES_DIR.glob('*.yar'))}
    if not filepaths:
        return None
    return yara.compile(filepaths=filepaths)


def scan_with_yara(data: bytes) -> list[dict]:
    """Return a list of match dicts: ``{rule, tags, meta, matched_strings}``."""
    rules = _compiled_rules()
    if rules is None:
        return []

    results: list[dict] = []
    for match in rules.match(data=data):
        matched_strings = sorted(
            {
                instance.matched_data[:80].decode('utf-8', 'replace')
                for string_match in match.strings
                for instance in string_match.instances[:5]
            }
        )[:_MAX_STRING_MATCHES]
        results.append(
            {
                'rule': match.rule,
                'tags': list(match.tags),
                'meta': dict(match.meta),
                'matched_strings': matched_strings,
            }
        )
    return results
