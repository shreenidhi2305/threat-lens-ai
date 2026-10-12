"""Single-container deployment: the API serves the built UI itself, and seeds demo data."""

import pytest
from fastapi.testclient import TestClient

from app.core import demo_seed
from app.core.config import settings
from app.core.demo_seed import seed_demo_data
from app.core.frontend import security_headers
from app.main import create_application


@pytest.fixture
def ui_client(tmp_path, monkeypatch):
    (tmp_path / "assets").mkdir()
    (tmp_path / "index.html").write_text("<!doctype html><title>ThreatLens</title><div id=root></div>")
    (tmp_path / "assets" / "app-abc123.js").write_text("console.log('hi')")
    (tmp_path / "favicon.svg").write_text("<svg/>")
    secret = tmp_path.parent / "secret.txt"
    secret.write_text("TOP SECRET")
    monkeypatch.setattr(settings, "SERVE_FRONTEND_DIR", str(tmp_path))
    return TestClient(create_application())


def test_ui_is_not_served_unless_configured():
    assert settings.SERVE_FRONTEND_DIR == ""
    assert TestClient(create_application()).get("/").status_code == 404


def test_serves_the_app_shell_with_security_headers(ui_client):
    r = ui_client.get("/")
    assert r.status_code == 200 and "<div id=root>" in r.text
    assert r.headers["cache-control"] == "no-cache"
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"


def test_client_side_routes_fall_back_to_the_shell(ui_client):
    for path in ("/alerts", "/admin", "/threats/some/deep/link"):
        r = ui_client.get(path)
        assert r.status_code == 200 and "<div id=root>" in r.text


def test_hashed_assets_are_cached_hard_and_typed(ui_client):
    r = ui_client.get("/assets/app-abc123.js")
    assert r.status_code == 200 and r.text == "console.log('hi')"
    assert "immutable" in r.headers["cache-control"]
    assert "javascript" in r.headers["content-type"]
    assert ui_client.get("/favicon.svg").headers["content-type"].startswith("image/svg")


def test_path_traversal_cannot_read_files_outside_the_build(ui_client):
    for path in ("/..%2fsecret.txt", "/%2e%2e/secret.txt", "/assets/..%2f..%2fsecret.txt", "/../secret.txt"):
        r = ui_client.get(path)
        assert "TOP SECRET" not in r.text


def test_real_routes_win_over_the_catch_all(ui_client):
    assert ui_client.get("/health").json() == {"status": "ok"}
    assert ui_client.get("/api/v1/auth/config").json()["mode"] == "dev"
    assert ui_client.get("/openapi.json").status_code == 200


def test_unknown_api_paths_are_a_json_404_not_the_app(ui_client):
    r = ui_client.get("/api/v1/does-not-exist")
    assert r.status_code == 404
    assert r.headers["content-type"].startswith("application/json")
    assert ui_client.get("/api/whatever").status_code == 404


def test_static_files_are_not_rate_limited(ui_client, monkeypatch):
    from app.core.rate_limit import limiter
    from app.core.runtime_settings import runtime_settings

    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    limiter.reset()
    runtime_settings.update({"RATE_LIMIT_PER_MINUTE": 10})
    try:
        assert all(ui_client.get("/assets/app-abc123.js").status_code == 200 for _ in range(25))
    finally:
        runtime_settings.reset()
        limiter.reset()


def test_hosts_that_embed_the_app_can_allow_their_origin(monkeypatch):
    monkeypatch.setattr(settings, "FRAME_ANCESTORS", "https://huggingface.co https://*.hf.space")
    headers = security_headers()
    assert "frame-ancestors https://huggingface.co https://*.hf.space" in headers["Content-Security-Policy"]
    assert "X-Frame-Options" not in headers


# --- demo seeding -----------------------------------------------------------------

class FakePipeline:
    def __init__(self):
        self.scans = []

    def scan(self, object_path, data, actor=None):
        self.scans.append((object_path, len(data), actor))


class FakeAlerts:
    def __init__(self):
        self.calls = []

    def list_alerts(self, status=None):
        return [type("A", (), {"id": f"a{i}"})() for i in range(4)]

    def set_status(self, alert_id, status, note=None):
        self.calls.append(("status", alert_id, status))

    def create_incident(self, ids, title):
        self.calls.append(("incident", tuple(ids), title))


class FakeStorage:
    @staticmethod
    def object_path_for(data, name):
        return f"hash/{name}"


def test_seeding_scans_the_bundled_samples_and_sets_up_examples(monkeypatch, tmp_path):
    from pathlib import Path

    samples = Path(__file__).resolve().parents[2] / "demo" / "samples"
    monkeypatch.setattr(settings, "DEMO_SAMPLES_DIR", str(samples))
    pipeline, alerts = FakePipeline(), FakeAlerts()
    assert seed_demo_data(pipeline, alerts, FakeStorage) == 8
    assert {s[0] for s in pipeline.scans} >= {"hash/trojan_downloader.bin", "hash/clean_notes.txt"}
    assert all(s[2] == "demo-seed" for s in pipeline.scans)
    assert ("status", "a3", "acknowledged") in alerts.calls
    assert any(c[0] == "incident" for c in alerts.calls)


def test_seeding_is_a_no_op_without_samples_and_never_raises(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "DEMO_SAMPLES_DIR", "")
    assert seed_demo_data(FakePipeline(), FakeAlerts(), FakeStorage) == 0
    monkeypatch.setattr(settings, "DEMO_SAMPLES_DIR", str(tmp_path / "missing"))
    assert seed_demo_data(FakePipeline(), FakeAlerts(), FakeStorage) == 0

    class Exploding(FakePipeline):
        def scan(self, *a, **k):
            raise RuntimeError("boom")

    from pathlib import Path

    monkeypatch.setattr(settings, "DEMO_SAMPLES_DIR", str(Path(__file__).resolve().parents[2] / "demo" / "samples"))
    assert seed_demo_data(Exploding(), FakeAlerts(), FakeStorage) == 0


def test_seeding_real_pipeline_end_to_end(monkeypatch):
    """Uses the real pipeline once, so the seeded data really appears in the dashboards."""
    from pathlib import Path

    from app.modules.threat_monitoring.service import threat_monitoring_service

    monkeypatch.setattr(settings, "DEMO_SAMPLES_DIR", str(Path(__file__).resolve().parents[2] / "demo" / "samples"))
    before = len(threat_monitoring_service.all_detections())
    assert demo_seed.seed_demo_data() == 8
    after = threat_monitoring_service.all_detections()
    assert len(after) == before + 8
    assert any(d.analyst == "demo-seed" and d.verdict_label == "malicious" for d in after)
