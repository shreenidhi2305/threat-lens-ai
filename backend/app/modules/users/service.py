"""User profiles and administrator user/role management.

Two backends, chosen automatically (like the rest of the platform):

* **Supabase** (``profiles`` + ``roles`` tables) when configured.
* **In-memory directory** for local development: users appear when they sign in with
  the dev login, and a role set by an administrator is applied on their next sign-in.

A user's role is read from their token, so a role change takes effect the next time
that user signs in.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone

from app.core.config import settings
from app.modules.users.schemas import ROLES, ManagedUser, UserProfile

# Local dev logins: the email prefix selects the default role.
DEV_ROLE_BY_PREFIX: dict[str, str] = {
    'analyst': 'Security Analyst',
    'soc': 'SOC Team Member',
    'admin': 'Administrator',
    'researcher': 'Researcher',
}
DEV_DEFAULT_ROLE = 'Security Analyst'


class LastAdministratorError(ValueError):
    pass


class UserNotFoundError(LookupError):
    pass


class UserService:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._dev: dict[str, ManagedUser] = {}
        for prefix, role in DEV_ROLE_BY_PREFIX.items():
            email = f'{prefix}@local'
            self._dev[email] = ManagedUser(id=email, email=email, role=role)

    # --- sign-in ---------------------------------------------------------
    def dev_login_role(self, email: str) -> str:
        """Role for a dev sign-in: the directory's (admin-assignable) role, else the prefix default."""
        email = email.strip().lower()
        prefix = email.split('@', 1)[0]
        with self._lock:
            known = self._dev.get(email)
            if known is None:
                known = ManagedUser(
                    id=email,
                    email=email,
                    role=DEV_ROLE_BY_PREFIX.get(prefix, DEV_DEFAULT_ROLE),
                    created_at=datetime.now(timezone.utc),
                )
                self._dev[email] = known
            known.last_login = datetime.now(timezone.utc)
            return known.role

    # --- own profile -------------------------------------------------------
    def get_me(self, user_id: str, roles: list[str] | None = None) -> UserProfile:
        if not settings.supabase_configured:
            known = self._dev.get(user_id.lower())
            return UserProfile(
                id=user_id,
                email=user_id if '@' in user_id else f'{user_id}@local',
                role=(roles or [known.role if known else DEV_DEFAULT_ROLE])[0],
                display_name=known.display_name if known else None,
            )

        from app.db.supabase import get_supabase_clients

        clients = get_supabase_clients()
        try:
            result = (
                clients.database.table('profiles')
                .select('id, email, display_name, roles(name)')
                .eq('id', user_id)
                .single()
                .execute()
            )
        except Exception:  # noqa: BLE001 - display_name column not migrated yet
            result = (
                clients.database.table('profiles')
                .select('id, email, roles(name)')
                .eq('id', user_id)
                .single()
                .execute()
            )
        return UserProfile(
            id=result.data['id'],
            email=result.data['email'],
            role=result.data['roles']['name'],
            display_name=result.data.get('display_name'),
        )

    def update_me(self, user_id: str, roles: list[str] | None, display_name: str) -> UserProfile:
        name = display_name.strip()
        if not name:
            raise ValueError('Display name cannot be empty')
        if not settings.supabase_configured:
            with self._lock:
                known = self._dev.get(user_id.lower())
                if known is None:
                    known = ManagedUser(
                        id=user_id, email=user_id, role=(roles or [DEV_DEFAULT_ROLE])[0]
                    )
                    self._dev[user_id.lower()] = known
                known.display_name = name
        else:
            from app.db.supabase import get_supabase_clients

            clients = get_supabase_clients()
            clients.database.table('profiles').update({'display_name': name}).eq('id', user_id).execute()
        return self.get_me(user_id, roles)

    # --- administration -------------------------------------------------------
    def list_users(self) -> list[ManagedUser]:
        if not settings.supabase_configured:
            with self._lock:
                return sorted((u.model_copy() for u in self._dev.values()), key=lambda u: u.email)

        from app.db.supabase import get_supabase_clients

        clients = get_supabase_clients()
        try:
            result = (
                clients.database.table('profiles')
                .select('id, email, display_name, created_at, roles(name)')
                .order('email')
                .execute()
            )
        except Exception:  # noqa: BLE001 - display_name column not migrated yet
            result = (
                clients.database.table('profiles')
                .select('id, email, created_at, roles(name)')
                .order('email')
                .execute()
            )
        return [
            ManagedUser(
                id=row['id'],
                email=row['email'],
                role=(row.get('roles') or {}).get('name', DEV_DEFAULT_ROLE),
                display_name=row.get('display_name'),
                created_at=row.get('created_at'),
            )
            for row in (result.data or [])
        ]

    def set_role(self, user_id: str, role: str) -> ManagedUser:
        if role not in ROLES:
            raise ValueError(f"Unknown role. Choose one of: {', '.join(ROLES)}")
        users = self.list_users()
        target = next((u for u in users if u.id == user_id), None)
        if target is None:
            raise UserNotFoundError(user_id)
        if (
            target.role == 'Administrator'
            and role != 'Administrator'
            and sum(1 for u in users if u.role == 'Administrator') <= 1
        ):
            raise LastAdministratorError('Cannot remove the last administrator')

        if not settings.supabase_configured:
            with self._lock:
                self._dev[user_id.lower()].role = role
        else:
            from app.db.supabase import get_supabase_clients

            clients = get_supabase_clients()
            role_row = clients.database.table('roles').select('id').eq('name', role).single().execute()
            clients.database.table('profiles').update({'role_id': role_row.data['id']}).eq(
                'id', user_id
            ).execute()
        return next(u for u in self.list_users() if u.id == user_id)


user_service = UserService()
