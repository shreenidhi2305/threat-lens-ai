from typing import Any

from app.db.supabase import get_supabase_clients


class FeedbackRepository:
    """Database operations for analyst verdict feedback (``analyst_feedback`` table)."""

    def upsert(self, row: dict[str, Any]) -> dict[str, Any]:
        clients = get_supabase_clients()
        result = clients.database.table('analyst_feedback').upsert(row, on_conflict='sha256').execute()
        return result.data[0] if result.data else row

    def list(self, limit: int = 2000) -> list[dict[str, Any]]:
        clients = get_supabase_clients()
        result = (
            clients.database.table('analyst_feedback')
            .select('*')
            .order('created_at', desc=True)
            .limit(limit)
            .execute()
        )
        return result.data or []
