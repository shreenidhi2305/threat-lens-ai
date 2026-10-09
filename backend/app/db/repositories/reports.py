from typing import Any

from app.db.supabase import get_supabase_clients


class ReportRepository:
    """Database operations for the generated-report history (``reports`` table:
    the audit trail of downloaded investigation/summary PDFs)."""

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


class AnalysisReportRepository:
    """Database operations for per-scan threat-prediction reports
    (``analysis_reports`` table: one persisted, revisitable report per scan,
    with the full analysis payload for later PDF regeneration)."""

    def __init__(self) -> None:
        self.table_name = 'analysis_reports'

    def create(self, report: dict[str, Any]) -> dict[str, Any]:
        clients = get_supabase_clients()

        result = (
            clients.database
            .table(self.table_name)
            .insert(report)
            .execute()
        )

        if not result.data:
            raise RuntimeError('Failed to create analysis report')

        return result.data[0]

    def list(self, limit: int = 100) -> list[dict[str, Any]]:
        clients = get_supabase_clients()

        result = (
            clients.database
            .table(self.table_name)
            .select("*")
            .order("created_at", desc=True)
            .limit(limit)
            .execute()
        )

        return result.data or []

    def get(self, report_id: str) -> dict[str, Any] | None:
        clients = get_supabase_clients()

        result = (
            clients.database
            .table(self.table_name)
            .select("*")
            .eq("id", report_id)
            .limit(1)
            .execute()
        )

        return result.data[0] if result.data else None
