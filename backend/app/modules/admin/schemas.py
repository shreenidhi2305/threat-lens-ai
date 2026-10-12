from typing import Any

from pydantic import BaseModel


class SettingsUpdateRequest(BaseModel):
    values: dict[str, Any]


class IntegrationStatus(BaseModel):
    id: str
    name: str
    description: str
    configured: bool
    healthy: bool | None = None
    destination: str | None = None
    detail: str | None = None
    testable: bool = False
    stats: dict[str, Any] = {}


class IntegrationTestResult(BaseModel):
    ok: bool
    error: str | None = None


class PlatformOverview(BaseModel):
    version: str
    environment: str
    uptime_seconds: int
    persistence: str  # supabase | in-memory
    auth_mode: str  # supabase | dev-login
    requests: dict[str, Any]
    totals: dict[str, int]
    models: dict[str, Any]
    audit_actions: dict[str, int]
    warnings: list[str]
