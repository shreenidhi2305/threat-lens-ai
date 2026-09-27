"""Storage for uploaded samples.

Two backends, chosen automatically:

* **Supabase Storage** when ``SUPABASE_URL`` / ``SUPABASE_SERVICE_KEY`` are set.
* **Local disk** (``backend/var/uploads/``) otherwise -- keeps local dev and the
  demo working without any cloud setup.

Samples are stored under their SHA-256 so identical uploads collapse to one
object. Uploaded files are treated as untrusted and are never executed.
"""

import hashlib
import re
from pathlib import Path

from app.core.config import settings

# backend/app/modules/file_analysis/storage.py -> parents[3] == backend/
_LOCAL_ROOT = Path(__file__).resolve().parents[3] / 'var' / 'uploads'
_SAFE_NAME = re.compile(r'[^A-Za-z0-9._-]')


def _safe_filename(filename: str) -> str:
    cleaned = _SAFE_NAME.sub('_', filename.strip()) or 'sample'
    return cleaned[:120]


def object_path_for(data: bytes, filename: str) -> str:
    """Deterministic storage key: ``<sha256>/<original-name>``."""
    digest = hashlib.sha256(data).hexdigest()
    return f'{digest}/{_safe_filename(filename)}'


def save_sample(data: bytes, filename: str) -> str:
    """Persist ``data`` and return its object path."""
    object_path = object_path_for(data, filename)

    if settings.supabase_configured:
        from app.db.supabase import get_supabase_clients

        clients = get_supabase_clients()
        bucket = clients.storage.storage.from_(settings.SUPABASE_STORAGE_BUCKET)
        bucket.upload(object_path, data, {'upsert': 'true'})
        return object_path

    destination = _LOCAL_ROOT / object_path
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    return object_path


def load_sample(object_path: str) -> bytes | None:
    """Return stored bytes for ``object_path``, or ``None`` if absent."""
    if settings.supabase_configured:
        from app.db.supabase import get_supabase_clients

        clients = get_supabase_clients()
        bucket = clients.storage.storage.from_(settings.SUPABASE_STORAGE_BUCKET)
        try:
            return bucket.download(object_path)
        except Exception:  # noqa: BLE001 - supabase raises assorted errors for "missing"
            return None

    source = _LOCAL_ROOT / object_path
    return source.read_bytes() if source.is_file() else None
