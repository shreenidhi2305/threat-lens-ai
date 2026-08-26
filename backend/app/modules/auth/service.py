from app.core.security import create_access_token
from app.modules.auth.schemas import TokenResponse


class AuthService:
    def login(self, email: str, password: str) -> TokenResponse:
        # Replace with real user verification + Supabase/Auth provider integration.
        token = create_access_token(subject=email)
        return TokenResponse(access_token=token)


auth_service = AuthService()
