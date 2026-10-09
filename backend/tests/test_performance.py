"""Regression tests for the performance work.

The optimised helpers must return exactly what the original (slower)
implementations returned, so each is checked against a straightforward reference
implementation. The upload tests cover the event-loop and size-limit behaviour.
"""

import math
import random
import re
import threading
import time
from collections import Counter

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.ml.features.extractor import _ascii_strings
from app.modules.file_analysis.analyzers import risk
from app.modules.file_analysis.analyzers.metadata import _printable_ratio, shannon_entropy
from app.modules.file_analysis.analyzers.strings import extract_strings


def _sample_bytes(seed: int = 7, size: int = 50_000) -> bytes:
    rng = random.Random(seed)
    noise = bytes(rng.getrandbits(8) for _ in range(size))
    return noise + b'\x00hello world\x00PowerShell -EncodedCommand AAA\x00ab\x00CMD.EXE /C dir\x00' + noise[:500]


# --- reference (original) implementations ------------------------------------

def _ref_extract_strings(data: bytes, min_length: int) -> list[str]:
    out, cur = [], []
    for byte in data:
        if 32 <= byte <= 126:
            cur.append(chr(byte))
            continue
        if len(cur) >= min_length:
            out.append(''.join(cur))
        cur = []
    if len(cur) >= min_length:
        out.append(''.join(cur))
    return out


def _ref_printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13)) / len(data)


def _ref_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


# --- equivalence ---------------------------------------------------------------

@pytest.mark.parametrize('min_length', [4, 5, 6])
def test_extract_strings_matches_reference(min_length):
    data = _sample_bytes()
    assert extract_strings(data, min_length=min_length) == _ref_extract_strings(data, min_length)


def test_extract_strings_limit_returns_prefix_of_full_result():
    data = _sample_bytes()
    full = extract_strings(data, min_length=6)
    assert extract_strings(data, min_length=6, limit=5) == full[:5]
    assert extract_strings(data, min_length=6, limit=10**6) == full


def test_extract_strings_edge_cases():
    assert extract_strings(b'') == []
    assert extract_strings(b'abc', min_length=4) == []
    assert extract_strings(b'abcd', min_length=4) == ['abcd']
    assert extract_strings(b'\x00abcdef\x00', min_length=6) == ['abcdef']


def test_ml_ascii_strings_matches_reference():
    data = _sample_bytes(seed=11)
    expected = [s.encode('ascii') for s in _ref_extract_strings(data, 5)]
    assert _ascii_strings(data, min_len=5) == expected


def test_printable_ratio_matches_reference():
    for data in (b'', b'plain text\n\t\r', bytes(range(256)), _sample_bytes()):
        assert _printable_ratio(data) == pytest.approx(_ref_printable_ratio(data))


def test_shannon_entropy_matches_reference():
    for data in (b'', b'\x00' * 100, b'abab', bytes(range(256)), _sample_bytes()):
        assert shannon_entropy(data) == pytest.approx(_ref_entropy(data), abs=1e-9)


def test_find_suspicious_strings_matches_case_insensitive_originals():
    samples = [
        b'x PowerShell -EncodedCommand AAA', b'CMD.EXE /C dir', b'VSSADMIN delete shadows /all',
        b'AmsiScanBuffer', b'Set-MpPreference -x', b'certutil -urlcache -f http://a',
        b'FromBase64String', b'MiMiKaTz', b'nothing suspicious here', b'WsCript.exe', b'RUNDLL32',
        b'schtasks /Create /tn x', b'-EP  Bypass', b'bitsadmin /transfer', _sample_bytes(),
    ]
    for data in samples:
        expected = [
            label for label, pattern in risk._SUSPICIOUS_STRING_PATTERNS.items() if pattern.search(data)
        ]
        assert risk.find_suspicious_strings(data) == expected


def test_lowercase_patterns_contain_no_uppercase_escapes():
    # The lowercase-pattern optimisation is only valid while no pattern uses an
    # uppercase escape such as \S, \W or \B (lowercasing would change their meaning).
    for pattern in risk._SUSPICIOUS_STRING_PATTERNS.values():
        assert not re.search(r'\\[A-Z]', pattern.pattern.decode('latin1'))


# --- upload endpoint -------------------------------------------------------------

@pytest.fixture()
def client():
    with TestClient(app) as test_client:  # `with` also exercises the startup warm-up
        yield test_client


@pytest.fixture()
def auth(client):
    response = client.post('/api/v1/auth/login', json={'email': 'analyst@local', 'password': 'x'})
    assert response.status_code == 200
    return {'Authorization': f"Bearer {response.json()['access_token']}"}


def test_upload_rejects_oversized_file_quickly(client, auth):
    data = b'A' * (33 * 1024 * 1024)
    started = time.perf_counter()
    response = client.post('/api/v1/files/upload', files={'file': ('big.bin', data)}, headers=auth)
    assert response.status_code == 413
    assert time.perf_counter() - started < 5


def test_upload_rejects_empty_file(client, auth):
    response = client.post('/api/v1/files/upload', files={'file': ('empty.bin', b'')}, headers=auth)
    assert response.status_code == 400


def test_responses_carry_timing_header(client):
    response = client.get('/health')
    assert response.status_code == 200
    assert float(response.headers['X-Process-Time']) >= 0


def test_scan_does_not_block_other_requests(client, auth, monkeypatch):
    """A slow scan must not stall unrelated requests (it used to freeze the event loop)."""
    from app.modules.file_analysis import router as upload_router

    release = threading.Event()
    original = upload_router.pipeline_service.scan

    def slow_scan(*args, **kwargs):
        release.wait(timeout=10)  # simulate a long CPU-bound scan
        return original(*args, **kwargs)

    monkeypatch.setattr(upload_router.pipeline_service, 'scan', slow_scan)

    outcome: dict = {}

    def do_upload():
        outcome['response'] = client.post(
            '/api/v1/files/upload', files={'file': ('a.bin', b'MZ' + b'x' * 2000)}, headers=auth
        )

    worker = threading.Thread(target=do_upload)
    worker.start()
    try:
        time.sleep(0.3)  # let the upload reach the (blocked) scan
        started = time.perf_counter()
        health = client.get('/health')
        elapsed = time.perf_counter() - started
        assert health.status_code == 200
        assert elapsed < 1.0, f'/health took {elapsed:.2f}s while a scan was running'
    finally:
        release.set()
        worker.join(timeout=20)
    assert outcome['response'].status_code == 201


# --- detection cache -------------------------------------------------------------

def test_detection_cache_reuses_rows_and_invalidates_on_record(monkeypatch):
    from types import SimpleNamespace

    from app.modules.threat_monitoring import service as svc

    monkeypatch.setattr(svc, 'settings', SimpleNamespace(supabase_configured=True))
    service = svc.ThreatMonitoringService()
    calls = {'n': 0}

    def fake_list(limit=100, level=None):
        calls['n'] += 1
        return []

    monkeypatch.setattr(service._repository, 'list', fake_list)
    monkeypatch.setattr(service._repository, 'create', lambda row: row)

    service.get_stats()
    service.get_snapshot()
    service.get_timeline()
    service.distinct_families()
    assert calls['n'] == 1, 'four reads in a row should hit Supabase once'

    service._cache = None  # what record() does after a new detection
    service.get_stats()
    assert calls['n'] == 2
