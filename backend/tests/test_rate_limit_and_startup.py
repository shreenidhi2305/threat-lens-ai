"""Milestone 4: API-gateway rate limiting and production start-up safety."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.config import Settings, settings
from app.core.rate_limit import RateLimitMiddleware, SlidingWindowLimiter, limiter
from app.core.runtime_settings import runtime_settings
from app.core.startup_checks import find_problems, validate_settings
from app.main import app

STRONG = "k" * 40


# --- the limiter ------------------------------------------------------------------

def test_sliding_window_allows_up_to_the_limit_then_blocks():
    lim = SlidingWindowLimiter(window_seconds=60)
    results = [lim.check("u", 3, now=t) for t in (0.0, 1.0, 2.0)]
    assert [r[0] for r in results] == [True, True, True]
    assert [r[1] for r in results] == [2, 1, 0]
    allowed, remaining, retry = lim.check("u", 3, now=3.0)
    assert (allowed, remaining) == (False, 0)
    assert 1 <= retry <= 60


def test_window_slides_and_keys_are_independent():
    lim = SlidingWindowLimiter(window_seconds=10)
    for t in (0.0, 1.0):
        lim.check("a", 2, now=t)
    assert lim.check("a", 2, now=2.0)[0] is False
    assert lim.check("b", 2, now=2.0)[0] is True  # another principal is unaffected
    assert lim.check("a", 2, now=10.5)[0] is True  # the first hit has aged out


# --- the middleware ------------------------------------------------------------------

@pytest.fixture
def limits_on(monkeypatch):
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    limiter.reset()
    runtime_settings.reset()
    yield
    runtime_settings.reset()
    limiter.reset()


def test_middleware_returns_429_with_retry_after(limits_on):
    runtime_settings.update({"RATE_LIMIT_PER_MINUTE": 10})
    mini = FastAPI()
    mini.add_middleware(RateLimitMiddleware)

    @mini.get("/api/v1/ping")
    def ping():
        return {"ok": True}

    @mini.get("/health")
    def health():
        return {"status": "ok"}

    c = TestClient(mini)
    for i in range(10):
        r = c.get("/api/v1/ping")
        assert r.status_code == 200
        assert r.headers["X-RateLimit-Limit"] == "10"
        assert r.headers["X-RateLimit-Remaining"] == str(9 - i)
    blocked = c.get("/api/v1/ping")
    assert blocked.status_code == 429
    assert int(blocked.headers["Retry-After"]) >= 1
    assert "Rate limit" in blocked.json()["detail"]
    assert c.get("/health").status_code == 200  # health checks are exempt


def test_login_attempts_have_their_own_stricter_budget(limits_on):
    runtime_settings.update({"LOGIN_RATE_LIMIT_PER_MINUTE": 3})
    c = TestClient(app)
    codes = [
        c.post("/api/v1/auth/login", json={"email": "analyst@local", "password": "x"}).status_code
        for _ in range(5)
    ]
    assert codes == [200, 200, 200, 429, 429]


def test_authenticated_users_are_limited_independently(limits_on):
    runtime_settings.update({"RATE_LIMIT_PER_MINUTE": 10})
    c = TestClient(app)
    tokens = {
        e: c.post("/api/v1/auth/login", json={"email": e, "password": "x"}).json()["access_token"]
        for e in ("analyst@local", "soc@local")
    }
    hit = lambda e: c.get("/api/v1/users/me", headers={"Authorization": f"Bearer {tokens[e]}"}).status_code
    assert [hit("analyst@local") for _ in range(11)][-1] == 429
    assert hit("soc@local") == 200


# --- production safety ---------------------------------------------------------------------

def _cfg(**kw) -> Settings:
    return Settings(_env_file=None, **kw)


def test_production_refuses_unsafe_defaults():
    errors, _ = find_problems(_cfg(APP_ENV="production"))
    assert any("JWT_SECRET_KEY" in e for e in errors)
    assert any("identity provider" in e for e in errors)
    with pytest.raises(RuntimeError, match="unsafe configuration"):
        validate_settings(_cfg(APP_ENV="production"))


def test_production_with_real_config_boots():
    cfg = _cfg(
        APP_ENV="production", JWT_SECRET_KEY=STRONG,
        SUPABASE_URL="https://x.supabase.co", SUPABASE_SERVICE_KEY="svc",
        CORS_ALLOW_ORIGINS="https://app.example.com", RATE_LIMIT_ENABLED=True,
    )
    errors, warnings = find_problems(cfg)
    assert errors == [] and warnings == []
    validate_settings(cfg)


def test_development_only_warns():
    errors, warnings = find_problems(_cfg(APP_ENV="development"))
    assert errors == []
    assert len(warnings) == 2


def test_dev_login_can_be_explicitly_allowed_in_production():
    # open dev login (any password) is never acceptable in production ...
    errors, _ = find_problems(_cfg(APP_ENV="production", ALLOW_DEV_LOGIN=True, JWT_SECRET_KEY=STRONG))
    assert any("dev login" in e and "DEV_LOGIN_PASSWORD" in e for e in errors)
    assert _cfg(APP_ENV="production", ALLOW_DEV_LOGIN=True).dev_login_enabled is True
    assert _cfg(APP_ENV="production").dev_login_enabled is False
    assert _cfg(APP_ENV="development").dev_login_enabled is True


def test_password_gated_demo_mode_is_allowed_in_production():
    base = dict(APP_ENV="production", ALLOW_DEV_LOGIN=True, JWT_SECRET_KEY=STRONG,
                CORS_ALLOW_ORIGINS="https://demo.example.com", RATE_LIMIT_ENABLED=True)
    errors, warnings = find_problems(_cfg(DEV_LOGIN_PASSWORD="a-long-shared-secret", **base))
    assert errors == []
    assert any("Demo mode" in w for w in warnings)  # still flagged, but it can boot
    validate_settings(_cfg(DEV_LOGIN_PASSWORD="a-long-shared-secret", **base))

    errors, _ = find_problems(_cfg(DEV_LOGIN_PASSWORD="short", **base))
    assert any("at least 12" in e for e in errors)


def test_shared_password_gates_the_dev_login(monkeypatch):
    c = TestClient(app)
    cfg = c.get("/api/v1/auth/config").json()
    assert cfg == {"mode": "dev", "dev_login": True, "password_required": False}

    monkeypatch.setattr(settings, "DEV_LOGIN_PASSWORD", "correct-horse-battery")
    assert c.get("/api/v1/auth/config").json()["password_required"] is True
    wrong = c.post("/api/v1/auth/login", json={"email": "admin@local", "password": "demo"})
    assert wrong.status_code == 401
    right = c.post("/api/v1/auth/login", json={"email": "admin@local", "password": "correct-horse-battery"})
    assert right.status_code == 200 and right.json()["access_token"]


def test_auth_config_reports_a_disabled_dev_login(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "production")
    cfg = TestClient(app).get("/api/v1/auth/config").json()
    assert cfg["dev_login"] is False


def test_dev_login_is_disabled_in_production(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "production")
    c = TestClient(app)
    resp = c.post("/api/v1/auth/login", json={"email": "admin@local", "password": "x"})
    assert resp.status_code == 503
    assert "not configured" in resp.json()["detail"]

    monkeypatch.setattr(settings, "ALLOW_DEV_LOGIN", True)
    assert c.post("/api/v1/auth/login", json={"email": "admin@local", "password": "x"}).status_code == 200
