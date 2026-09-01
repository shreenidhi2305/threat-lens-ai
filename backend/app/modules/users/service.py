from app.db.supabase import get_supabase_clients
from app.modules.users.schemas import UserProfile


class UserService:
    def get_me(self, user_id: str) -> UserProfile:
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