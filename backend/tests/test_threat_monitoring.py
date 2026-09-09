from types import SimpleNamespace

from app.modules.threat_monitoring.service import ThreatMonitoringService



from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)
def test_record_keeps_detection_when_supabase_fails(monkeypatch):
    service = ThreatMonitoringService()

    # Make the settings property report that Supabase is configured.
    monkeypatch.setattr(
        "app.modules.threat_monitoring.service.settings",
        SimpleNamespace(supabase_configured=True),
    )

    # Make the repository fail.
    def failing_create(_detection):
        raise RuntimeError("Supabase connection failed")

    monkeypatch.setattr(
        service._repository,
        "create",
        failing_create,
    )

    result = SimpleNamespace(
        verdict=SimpleNamespace(
            label="malicious",
            score=90,
            level="high",
            family="Test Malware",
            agreement="agree",
        ),
        ml=None,
        hashes=SimpleNamespace(
            sha256="abc123",
        ),
        object_path="test.exe",
        yara_matches=[],
        signature_match=SimpleNamespace(
            matched=False,
            name=None,
        ),
        risk=SimpleNamespace(
            score=90,
            level="high",
        ),
    )

    detection = service.record(result)

    assert detection.sha256 == "abc123"
    assert detection.verdict_label == "malicious"

    # The detection should still be available in memory.
    detections = service.list_detections()

    assert len(detections) == 1
    assert detections[0].sha256 == "abc123"

def test_list_detections_reads_from_supabase(monkeypatch):
    service = ThreatMonitoringService()

    monkeypatch.setattr(
        "app.modules.threat_monitoring.service.settings",
        SimpleNamespace(supabase_configured=True),
    )

    fake_rows = [
        {
            "id": "detection-1",
            "at": "2026-09-09T10:00:00+00:00",
            "sha256": "abc123",
            "filename": "malware.exe",
            "verdict_label": "malicious",
            "score": 95,
            "level": "high",
            "family": "Test Malware",
            "ml_probability": 0.98,
            "ml_category": "Trojan",
            "yara_rule_count": 2,
            "signature": None,
            "model_version": "test-model",
            "agreement": "agree",
            "analyst": None,
        }
    ]

    def fake_list(limit=100, level=None):
        assert limit == 100
        assert level is None
        return fake_rows

    monkeypatch.setattr(
        service._repository,
        "list",
        fake_list,
    )

    detections = service.list_detections()

    assert len(detections) == 1
    assert detections[0].id == "detection-1"
    assert detections[0].sha256 == "abc123"
    assert detections[0].verdict_label == "malicious"
    assert detections[0].score == 95

def test_detections_endpoint_returns_detection_history(monkeypatch):
    fake_detection = SimpleNamespace(
        id="detection-1",
        at="2026-09-09T10:00:00+00:00",
        sha256="abc123",
        filename="malware.exe",
        verdict_label="malicious",
        score=95,
        level="high",
        family="Test Malware",
        ml_probability=0.98,
        ml_category="Trojan",
        yara_rule_count=2,
        signature=None,
        model_version="test-model",
        agreement="agree",
        analyst=None,
    )

    monkeypatch.setattr(
        "app.modules.threat_monitoring.router.threat_monitoring_service.list_detections",
        lambda limit=100, level=None: [fake_detection],
    )

    response = client.get(
        "/api/v1/threats/detections",
        headers={
            "Authorization": f"Bearer "
            f'{client.post("/api/v1/auth/login", json={"email": "soc@local", "password": "x"}).json()["access_token"]}'
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert len(data) == 1
    assert data[0]["id"] == "detection-1"
    assert data[0]["sha256"] == "abc123"
    assert data[0]["verdict_label"] == "malicious"
    assert data[0]["score"] == 95

def test_list_detections_maps_supabase_fields(monkeypatch):
    service = ThreatMonitoringService()

    monkeypatch.setattr(
        "app.modules.threat_monitoring.service.settings",
        SimpleNamespace(supabase_configured=True),
    )

    fake_rows = [
        {
            "id": "detection-2",
            "created_at": "2026-09-09T11:00:00+00:00",
            "sha256": "def456",
            "filename": "suspicious.exe",
            "verdict_label": "suspicious",
            "score": 70,
            "level": "medium",
            "family": None,
            "ml_probability": 0.75,
            "ml_category": "Suspicious",
            "yara_rule_count": 1,
            "signature": None,
            "model_version": "test-model",
            "agreement": "rules-only",
            "analyst_id": None,
        }
    ]

    monkeypatch.setattr(
        service._repository,
        "list",
        lambda limit=100, level=None: fake_rows,
    )

    detections = service.list_detections()

    assert len(detections) == 1
    assert detections[0].id == "detection-2"
    assert detections[0].at.isoformat() == "2026-09-09T11:00:00+00:00"
    assert detections[0].analyst is None
    assert detections[0].filename == "suspicious.exe"
    assert detections[0].level == "medium"