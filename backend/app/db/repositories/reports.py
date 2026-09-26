from typing import Any

from app.db.supabase import get_supabase_clients


class ReportRepository:
    """Database access for threat prediction reports."""

    def __init__(self) -> None:
        self.table_name = "reports"

    def create(self, report: dict[str, Any]) -> dict[str, Any]:
        clients = get_supabase_clients()

        response = (
            clients.database
            .table(self.table_name)
            .insert(report)
            .execute()
        )

        if not response.data:
            raise RuntimeError("Failed to create report")

        return response.data[0]

    def list(self) -> list[dict[str, Any]]:
        clients = get_supabase_clients()

        response = (
            clients.database
            .table(self.table_name)
            .select("*")
            .order("created_at", desc=True)
            .execute()
        )

        return response.data or []

    def get(self, report_id: str) -> dict[str, Any] | None:
        clients = get_supabase_clients()

        response = (
            clients.database
            .table(self.table_name)
            .select("*")
            .eq("id", report_id)
            .limit(1)
            .execute()
        )

        if not response.data:
            return None

        return response.data[0]