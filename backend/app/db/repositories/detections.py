from typing import Any

from app.db.supabase import get_supabase_clients


class DetectionRepository:
    """Database operations for detection logs."""

    def create(self, detection: dict[str, Any]) -> dict[str, Any]:
        clients = get_supabase_clients()

        result = (
            clients.database
            .table("detections")
            .insert(detection)
            .execute()
        )

        return result.data[0]

    def list(
        self,
        limit: int = 100,
        level: str | None = None,
    ) -> list[dict[str, Any]]:
        clients = get_supabase_clients()

        query = (
            clients.database
            .table("detections")
            .select("*")
            .order("created_at", desc=True)
            .limit(limit)
        )

        if level:
            query = query.eq("level", level)

        result = query.execute()

        return result.data