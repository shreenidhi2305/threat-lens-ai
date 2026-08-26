from app.modules.users.schemas import UserProfile


class UserService:
    def get_me(self, user_id: str) -> UserProfile:
        return UserProfile(id=user_id, email='user@example.com', role='Security Analyst')


user_service = UserService()
