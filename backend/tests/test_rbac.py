"""RBAC smoke tests using the local dev login (Supabase not configured)."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _token(email: str) -> str:
    return client.post("/api/v1/auth/login", json={"email": email, "password": "x"}).json()[
        "access_token"
    ]


def _headers(email: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {_token(email)}"}


def test_dev_login_assigns_role_from_email_prefix():
    assert client.get("/api/v1/users/me", headers=_headers("soc@local")).json()["role"] == "SOC Team Member"
    assert client.get("/api/v1/users/me", headers=_headers("admin@local")).json()["role"] == "Administrator"
    assert client.get("/api/v1/users/me", headers=_headers("whoever@local")).json()["role"] == "Security Analyst"


def test_protected_endpoint_rejects_missing_token():
    assert client.get("/api/v1/threats/snapshot").status_code == 401


def test_protected_endpoint_rejects_wrong_role():
    # SOC Team Member is not allowed to run static analysis scans.
    resp = client.post(
        "/api/v1/files/scan", json={"object_path": "x"}, headers=_headers("soc@local")
    )
    assert resp.status_code == 403


def test_protected_endpoint_allows_correct_role():
    resp = client.post(
        "/api/v1/files/scan", json={"object_path": "x"}, headers=_headers("analyst@local")
    )
    assert resp.status_code == 200

    # ...and SOC Team Member *is* allowed on the threat dashboard.
    assert client.get("/api/v1/threats/snapshot", headers=_headers("soc@local")).status_code == 200
