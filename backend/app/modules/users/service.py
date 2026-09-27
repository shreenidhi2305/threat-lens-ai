from app.core.config import settings
from app.modules.users.schemas import UserProfile


class UserService:
    def get_me(self, user_id: str, roles: list[str] | None = None) -> UserProfile:
        if not settings.supabase_configured:
            return UserProfile(
                id=user_id,
                email=user_id if '@' in user_id else f'{user_id}@local',
                role=(roles or ['Security Analyst'])[0],
            )

        from app.db.supabase import get_supabase_clients

        clients = get_supabase_clients()
        result = (
            clients.database.table('profiles')
            .select('id, email, roles(name)')
            .eq('id', user_id)
            .single()
            .execute()
        )
        return UserProfile(id=result.data['id'], email=result.data['email'], role=result.data['roles']['name'])


user_service = UserService()
