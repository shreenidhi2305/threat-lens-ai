from app.modules.file_analysis.analyzers.yara import scan_with_yara


def test_yara_detects_suspicious_powershell():
    data = b"powershell -Command Get-Date"

    matches = scan_with_yara(data)

    assert len(matches) == 1
    assert matches[0]["rule"] == "Suspicious_PowerShell"


def test_yara_returns_empty_for_clean_data():
    data = b"Hello ThreatLens AI"

    matches = scan_with_yara(data)

    assert matches == []