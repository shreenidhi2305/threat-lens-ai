from fastapi.testclient import TestClient

from app.main import app
from app.modules.file_analysis.service import file_analysis_service

PE_BYTES = b"MZ" + b"\x00" * 0x3A + (0x40).to_bytes(4, "little") + b"PE\x00\x00" + b"\x00" * 64


def _auth_header(client: TestClient, email: str = "analyst@local") -> dict[str, str]:
    """Log in via the local dev login and return a bearer auth header."""
    token = client.post(
        "/api/v1/auth/login", json={"email": email, "password": "x"}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_service_combines_hashing_and_metadata():
    result = file_analysis_service.analyze_static_file("uploads/invoice.exe", PE_BYTES)

    assert result.sha256 == result.hashes.sha256
    assert result.md5 == result.hashes.md5
    assert len(result.hashes.sha256) == 64
    assert len(result.hashes.sha1) == 40
    assert len(result.hashes.md5) == 32

    assert result.metadata.size_bytes == len(PE_BYTES)
    assert result.metadata.file_type == "PE executable (Windows)"
    assert result.metadata.extension == ".exe"
    assert result.metadata.extension_matches_content is True


def test_scan_endpoint_requires_authentication():
    client = TestClient(app)
    assert client.post("/api/v1/files/scan", json={"object_path": "x"}).status_code == 401


def test_scan_endpoint_returns_hashes_and_metadata():
    client = TestClient(app)
    response = client.post(
        "/api/v1/files/scan",
        json={"object_path": "samples/a.bin"},
        headers=_auth_header(client),
    )

    assert response.status_code == 200
    body = response.json()
    assert set(body["hashes"]) == {"md5", "sha1", "sha256"}
    assert body["metadata"]["size_bytes"] == len(b"samples/a.bin")
    assert "shannon_entropy" in body["metadata"]
    assert body["signature_match"]["matched"] is False
