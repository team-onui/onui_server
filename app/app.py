from datetime import timedelta, datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from pyotp import TOTP
from sqlalchemy.orm import Session

from app.core.config import get_setting
from app.db.base import create_user, exist_by_email, get_db, select_user_by_username
from app.db.base_class import Base
from app.db.session import db_engine
from app.dto import SignUpRequest, CheckRequest
from app.model import schemas
from app.security.security import pwd_context


def create_tables():
    Base.metadata.create_all(bind=db_engine)


def get_application():
    create_tables()
    return FastAPI()


settings = get_setting()

app = get_application()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/Oauth2/token")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def authenticate_user(db: Session, username: str, password: str):
    user = select_user_by_username(username, db)
    if not user or not verify_password(password[:-6], user.hashed_password) or not TOTP(user.otp_secret).verify(
            password[-6:]):
        return False
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    data.update({"exp": expire})
    return jwt.encode(data, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


@app.get("/auth/check")
async def duplicated_user_check(request: CheckRequest):
    return exist_by_email(request.email)


@app.post("/auth/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXP)
    )

    return {"access_token": access_token, "token_type": "bearer"}


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        username: str = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]).get("sub")

        user = select_user_by_username(schemas.TokenData(username=username).username, db)
    except JWTError:
        raise HTTPException(
            status_code=401,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


@app.post("/auth", response_model=schemas.UserDto)
def sign_up(request: schemas.CreateUser, db: Session = Depends(get_db)):
    if not exist_by_email(request.username, db):
        return create_user(db, request).to_dto()
    else:
        HTTPException(status_code=409, detail="Duplicated user")
