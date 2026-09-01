from app.core.security import create_access_token
from app.db.supabase import get_supabase_clients
from app.modules.auth.schemas import TokenResponse


class AuthService:
    def login(self, email: str, password: str) -> TokenResponse:
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


auth_service = AuthService()