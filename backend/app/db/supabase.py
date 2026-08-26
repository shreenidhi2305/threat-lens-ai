from dataclasses import dataclass

from supabase import Client, create_client

from app.core.config import settings


@dataclass
class SupabaseClients:
    database: Client
    storage: Client


def get_supabase_clients() -> SupabaseClients:
    client = create_client(settings.SUPABASE_URL, settings.SUPABASE_SERVICE_KEY)
    return SupabaseClients(database=client, storage=client)
