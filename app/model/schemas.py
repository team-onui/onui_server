from typing import Optional
from uuid import UUID

from pydantic import BaseModel


class Tokens(BaseModel):
    access_token: str
    refresh_token: str


class UserBase(BaseModel):
    username: str
    email: str
    full_name: Optional[str] = None


class CreateUser(UserBase):
    password: str
    role: str = 'general'


class UserDto(UserBase):
    id: UUID or str or bytes
    disabled: bool = False

    class Config:
        orm_mode = True


class ReIssue(BaseModel):
    access_token: str
    refresh_token: str
