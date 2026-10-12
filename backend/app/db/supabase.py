import functools
from dataclasses import dataclass

from supabase import Client, create_client

from app.core.config import settings


@dataclass
class SupabaseClients:
    database: Client
    storage: Client


@functools.lru_cache(maxsize=2)
def _client(url: str, key: str) -> Client:
    # Building a client sets up a new HTTP session; do it once per credential pair,
    # not on every repository call.
    return create_client(url, key)


def get_supabase_clients() -> SupabaseClients:
    client = _client(settings.SUPABASE_URL, settings.SUPABASE_SERVICE_KEY)
    return SupabaseClients(database=client, storage=client)
