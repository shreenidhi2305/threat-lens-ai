import logging

from app.core.config import settings
from app.core.security import create_access_token
from app.modules.auth.schemas import TokenResponse
from app.modules.users.service import user_service

logger = logging.getLogger(__name__)


class AuthNotConfiguredError(RuntimeError):
    """No identity provider is configured and the dev login is disabled."""


class AuthService:
    def login(self, email: str, password: str) -> TokenResponse:
        if not settings.supabase_configured:
            return self._dev_login(email)
        return self._supabase_login(email, password)

    def _supabase_login(self, email: str, password: str) -> TokenResponse:
        from app.db.supabase import get_supabase_clients

        clients = get_supabase_clients()

        auth_response = clients.database.auth.sign_in_with_password(
            {'email': email, 'password': password}
        )
        user = auth_response.user
        if user is None:
            raise ValueError('Invalid credentials')

        profile = (
            clients.database.table('profiles')
            .select('role_id, roles(name)')
            .eq('id', user.id)
            .single()
            .execute()
        )
        role_name = profile.data['roles']['name']

        token = create_access_token(subject=user.id, roles=[role_name])
        return TokenResponse(access_token=token)

    def _dev_login(self, email: str) -> TokenResponse:
        """Local-development login: any password; the role comes from the user directory."""
        if not settings.dev_login_enabled:
            raise AuthNotConfiguredError('Authentication is not configured on this server')
        email = email.strip().lower()
        role = user_service.dev_login_role(email)
        logger.warning('Supabase not configured; issuing dev token for %s as %s', email, role)
        token = create_access_token(subject=email, roles=[role])
        return TokenResponse(access_token=token)


auth_service = AuthService()
