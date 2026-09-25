from typing import Any

from app.db.supabase import get_supabase_clients


class NotificationRepository:
    """Database operations for the in-app notification feed."""

    def create(self, notification: dict[str, Any]) -> dict[str, Any]:
        clients = get_supabase_clients()

        result = (
            clients.database
            .table("notifications")
            .insert(notification)
            .execute()
        )

        return result.data[0]

    def list(self, limit: int = 100) -> list[dict[str, Any]]:
        clients = get_supabase_clients()

        result = (
            clients.database
            .table("notifications")
            .select("*")
            .order("created_at", desc=True)
            .limit(limit)
            .execute()
        )

        return result.data

    def mark_read(self, notification_id: str) -> dict[str, Any]:
        clients = get_supabase_clients()

        result = (
            clients.database
            .table("notifications")
            .update({"read": True})
            .eq("id", notification_id)
            .execute()
        )

        return result.data[0] if result.data else {}

    def mark_all_read(self) -> None:
        clients = get_supabase_clients()

        (
            clients.database
            .table("notifications")
            .update({"read": True})
            .eq("read", False)
            .execute()
        )
