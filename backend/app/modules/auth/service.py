import logging

from app.core.config import settings
from app.core.security import create_access_token
from app.modules.auth.schemas import TokenResponse

logger = logging.getLogger(__name__)

# Local-development login shortcut used only when Supabase is not configured.
# The email prefix selects the role so RBAC can be exercised without a database.
_DEV_ROLE_BY_EMAIL: dict[str, str] = {
    'analyst': 'Security Analyst',
    'soc': 'SOC Team Member',
    'admin': 'Administrator',
    'researcher': 'Researcher',
}
_DEV_DEFAULT_ROLE = 'Security Analyst'


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
        prefix = email.split('@', 1)[0].lower()
        role = _DEV_ROLE_BY_EMAIL.get(prefix, _DEV_DEFAULT_ROLE)
        logger.warning('Supabase not configured; issuing dev token for %s as %s', email, role)
        token = create_access_token(subject=email, roles=[role])
        return TokenResponse(access_token=token)


auth_service = AuthService()
