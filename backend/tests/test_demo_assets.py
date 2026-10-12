"""The demo corpus is matched by SHA-256 against the signature database, so the files must
stay byte-for-byte identical. A Windows checkout with line-ending conversion silently broke
the headline "Known Trojan" demo once; this keeps it from happening again."""

import hashlib
import json
from pathlib import Path

import pytest

from app.modules.file_analysis.service import file_analysis_service

ROOT = Path(__file__).resolve().parents[2]
SAMPLES = ROOT / "demo" / "samples"
SIGNATURES = ROOT / "backend" / "app" / "modules" / "file_analysis" / "data" / "signatures.json"


@pytest.mark.parametrize(
    "name,family",
    [("trojan_downloader.bin", "trojan"), ("README_TO_DECRYPT.txt", "ransomware")],
)
def test_signature_samples_are_intact_and_detected(name, family):
    path = SAMPLES / name
    assert path.is_file(), "run `python demo/generate_samples.py`"
    data = path.read_bytes()
    assert hashlib.sha256(data).hexdigest() in SIGNATURES.read_text(encoding="utf-8"), (
        f"{name} no longer matches the signature database - was its line-ending changed? "
        "`demo/samples/* -text` in .gitattributes should prevent that."
    )
    result = file_analysis_service.analyze_static_file(name, data)
    assert result.signature_match.matched
    assert family in (result.signature_match.type or "").lower() + (result.signature_match.name or "").lower()


def test_gitattributes_protects_the_samples():
    attrs = (ROOT / ".gitattributes").read_text(encoding="utf-8")
    assert "demo/samples/* -text" in attrs


def test_signature_database_is_valid_json_with_entries():
    sigs = json.loads(SIGNATURES.read_text(encoding="utf-8"))["signatures"]
    assert len(sigs) >= 2
