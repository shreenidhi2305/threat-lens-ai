from app.db.repositories.detections import DetectionRepository


class FakeTable:
    def __init__(self):
        self.inserted_data = None

    def insert(self, data):
        self.inserted_data = data
        return self

    def execute(self):
        return type(
            "Response",
            (),
            {"data": [self.inserted_data]},
        )()


class FakeDatabase:
    def __init__(self):
        self.table_instance = FakeTable()

    def table(self, name):
        assert name == "detections"
        return self.table_instance


class FakeClients:
    def __init__(self):
        self.database = FakeDatabase()


def test_create_inserts_detection_into_detections_table(monkeypatch):
    fake_clients = FakeClients()

    monkeypatch.setattr(
        "app.db.repositories.detections.get_supabase_clients",
        lambda: fake_clients,
    )

    detection = {
        "id": "test-detection-id",
        "sha256": "abc123",
        "filename": "sample.exe",
        "verdict_label": "malicious",
        "score": 95,
        "level": "high",
        "family": "Trojan",
        "ml_probability": 0.98,
        "ml_category": "Trojan",
        "yara_rule_count": 2,
        "signature": None,
        "model_version": "dike-m2-2026.09",
        "agreement": "agree",
        "analyst_id": None,
    }

    repository = DetectionRepository()
    result = repository.create(detection)

    assert result == detection
    assert fake_clients.database.table_instance.inserted_data == detection

def test_list_returns_detections_from_detections_table(monkeypatch):
    fake_clients = FakeClients()

    fake_data = [
        {
            "id": "detection-1",
            "sha256": "abc123",
            "filename": "malware.exe",
            "verdict_label": "malicious",
            "score": 95,
            "level": "high",
            "created_at": "2026-09-09T10:00:00+00:00",
        },
        {
            "id": "detection-2",
            "sha256": "def456",
            "filename": "sample.exe",
            "verdict_label": "suspicious",
            "score": 60,
            "level": "medium",
            "created_at": "2026-09-09T09:00:00+00:00",
        },
    ]

    class ListTable:
        def select(self, _columns):
            return self

        def order(self, _column, desc=False):
            assert _column == "created_at"
            assert desc is True
            return self

        def limit(self, value):
            assert value == 100
            return self

        def eq(self, column, value):
            return self

        def execute(self):
            return type("Response", (), {"data": fake_data})()

    fake_clients.database.table = lambda name: ListTable()

    monkeypatch.setattr(
        "app.db.repositories.detections.get_supabase_clients",
        lambda: fake_clients,
    )

    repository = DetectionRepository()

    result = repository.list()

    assert result == fake_data