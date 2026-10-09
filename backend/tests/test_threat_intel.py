"""Milestone 3: VirusTotal threat-intelligence enrichment (best-effort, never raises)."""

import requests

from app.modules.threat_intel.service import ThreatIntelService

SHA256 = "e" * 64


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict | None = None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


def test_not_configured_returns_gracefully(monkeypatch):
    monkeypatch.setattr("app.modules.threat_intel.service.settings.VIRUSTOTAL_API_KEY", "")
    result = ThreatIntelService().lookup_hash(SHA256)
    assert result.configured is False
    assert result.available is False


def test_unknown_hash_returns_unavailable(monkeypatch):
    monkeypatch.setattr("app.modules.threat_intel.service.settings.VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(
        "app.modules.threat_intel.service.requests.get",
        lambda *a, **k: _FakeResponse(404),
    )
    result = ThreatIntelService().lookup_hash(SHA256)
    assert result.configured is True
    assert result.available is False
    assert "not seen" in (result.reason or "").lower()


def test_known_malicious_hash_is_parsed(monkeypatch):
    monkeypatch.setattr("app.modules.threat_intel.service.settings.VIRUSTOTAL_API_KEY", "test-key")
    payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 40,
                    "suspicious": 2,
                    "undetected": 20,
                    "harmless": 8,
                },
                "reputation": -10,
            }
        }
    }
    monkeypatch.setattr(
        "app.modules.threat_intel.service.requests.get",
        lambda *a, **k: _FakeResponse(200, payload),
    )
    result = ThreatIntelService().lookup_hash(SHA256)
    assert result.configured is True
    assert result.available is True
    assert result.malicious == 40
    assert result.total_engines == 70
    assert result.permalink and SHA256 in result.permalink


def test_network_error_never_raises(monkeypatch):
    monkeypatch.setattr("app.modules.threat_intel.service.settings.VIRUSTOTAL_API_KEY", "test-key")

    def _raise(*a, **k):
        raise requests.ConnectionError("boom")

    monkeypatch.setattr("app.modules.threat_intel.service.requests.get", _raise)
    result = ThreatIntelService().lookup_hash(SHA256)
    assert result.available is False
    assert result.configured is True


def test_rate_limit_returns_unavailable(monkeypatch):
    monkeypatch.setattr("app.modules.threat_intel.service.settings.VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(
        "app.modules.threat_intel.service.requests.get",
        lambda *a, **k: _FakeResponse(429),
    )
    result = ThreatIntelService().lookup_hash(SHA256)
    assert result.available is False
    assert "rate limit" in (result.reason or "").lower()
