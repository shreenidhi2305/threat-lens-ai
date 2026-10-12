from typing import Any

from app.db.supabase import get_supabase_clients


class AlertRepository:
    """Database operations for alerts (``alerts`` table)."""

    def upsert(self, alert: dict[str, Any]) -> dict[str, Any]:
        clients = get_supabase_clients()
        result = clients.database.table('alerts').upsert(alert).execute()
        return result.data[0] if result.data else alert

    def list(self, limit: int = 1000) -> list[dict[str, Any]]:
        clients = get_supabase_clients()
        result = (
            clients.database.table('alerts')
            .select('*')
            .order('created_at', desc=True)
            .limit(limit)
            .execute()
        )
        return result.data or []


class IncidentRepository:
    """Database operations for incidents (``incidents`` table)."""

    def upsert(self, incident: dict[str, Any]) -> dict[str, Any]:
        clients = get_supabase_clients()
        result = clients.database.table('incidents').upsert(incident).execute()
        return result.data[0] if result.data else incident

    def list(self, limit: int = 500) -> list[dict[str, Any]]:
        clients = get_supabase_clients()
        result = (
            clients.database.table('incidents')
            .select('*')
            .order('created_at', desc=True)
            .limit(limit)
            .execute()
        )
        return result.data or []
