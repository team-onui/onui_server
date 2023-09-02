import enum
from uuid import uuid4, UUID

from pydantic import BaseModel
from sqlalchemy import Column, BINARY, BIGINT, Enum, VARCHAR, CHAR
from sqlalchemy.dialects.mysql import BIT

from app.db.base_class import Base
from app.model.schemas import UserDto


class Role(str, enum.Enum):
    user = 'general'
    admin = 'admin'


class User(Base):
    __tablename__ = "user"
    pk = Column(BIGINT, primary_key=True, autoincrement=True)
    id = Column(BINARY(16), default=uuid4().bytes, unique=True, nullable=False)
    email = Column(VARCHAR(30), unique=True, index=True, nullable=False)
    username = Column(VARCHAR(30), unique=True, index=True)
    full_name = Column(VARCHAR(30))
    hashed_password = Column(CHAR(60), nullable=False)
    otp_secret = Column(VARCHAR(100), nullable=False)
    disabled = Column(BIT, default=False, nullable=False)
    role = Column(Enum(Role), nullable=False)

    def to_dto(self) -> UserDto:
        return UserDto(id=UUID(bytes=self.id), username=self.username, email=self.email, role=self.role)
