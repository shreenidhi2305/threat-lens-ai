from typing import Any

from app.db.supabase import get_supabase_clients


class ReportRepository:
    """Database operations for the generated-report history."""

    def create(self, report: dict[str, Any]) -> dict[str, Any]:
        clients = get_supabase_clients()

        result = (
            clients.database
            .table("reports")
            .insert(report)
            .execute()
        )

        return result.data[0]

    def list(self, limit: int = 100) -> list[dict[str, Any]]:
        clients = get_supabase_clients()

        result = (
            clients.database
            .table("reports")
            .select("*")
            .order("created_at", desc=True)
            .limit(limit)
            .execute()
        )

        return result.data
