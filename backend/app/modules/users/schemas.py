from datetime import datetime

from pydantic import BaseModel, Field

ROLES = ('Security Analyst', 'SOC Team Member', 'Administrator', 'Researcher')


class UserProfile(BaseModel):
    id: str
    email: str
    role: str
    display_name: str | None = None


class UpdateProfileRequest(BaseModel):
    display_name: str = Field(min_length=1, max_length=60)


class ManagedUser(BaseModel):
    """A user as seen by an administrator."""

    id: str
    email: str
    role: str
    display_name: str | None = None
    created_at: datetime | None = None
    last_login: datetime | None = None


class RoleChangeRequest(BaseModel):
    role: str
