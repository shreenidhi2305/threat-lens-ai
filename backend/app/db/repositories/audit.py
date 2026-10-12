from typing import Any

from app.db.supabase import get_supabase_clients


class AuditRepository:
    """Database operations for the administrator activity log (``audit_log``)."""

    def create(self, event: dict[str, Any]) -> dict[str, Any]:
        clients = get_supabase_clients()
        result = clients.database.table('audit_log').insert(event).execute()
        return result.data[0] if result.data else event

    def list(self, limit: int = 200) -> list[dict[str, Any]]:
        clients = get_supabase_clients()
        result = (
            clients.database.table('audit_log')
            .select('*')
            .order('created_at', desc=True)
            .limit(limit)
            .execute()
        )
        return result.data or []
