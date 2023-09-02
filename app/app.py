from datetime import timedelta, datetime

from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from redis import Redis
from sqlalchemy.orm import Session

from app.core.config import get_setting
from app.db.base import create_user, exist_by_username_and_email, get_db, select_user_by_username, create_redis, \
    get_redis, select_redis, delete_redis, exist_by_username
from app.db.base_class import Base
from app.db.session import db_engine
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


def authenticate_user(username: str, password: str, db: Session):
    user = select_user_by_username(username, db)

    if not pwd_context.verify(password, user.hashed_password):
        raise HTTPException(
            status_code=401,
            detail="Incorrect password exception",
        )

    return user


def create_refresh_token(sub: str, db: Redis):
    data = {
        'typ': 'JWT',
        'exp': datetime.utcnow() + timedelta(minutes=settings.REFRESH_TOKEN_EXP)
    }

    token = jwt.encode(data, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

    create_redis(sub, token, db)

    return token


def create_access_token(sub: str):
    data = {
        "sub": sub,
        'typ': 'JWT',
        'exp': datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXP)
    }
    return jwt.encode(data, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_tokens(sub: str, db: Redis):
    if select_redis(sub, db) is not None:
        delete_redis(sub, db)

    return {"access_token": create_access_token(sub), "refresh_token": create_refresh_token(sub, db)}


def validation_token(token: str):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except JWTError:
        raise HTTPException(
            status_code=401,
            detail="Invalid token exception",
        )

    if int(datetime.now().timestamp()) > int(payload.get("exp")):
        raise HTTPException(status_code=403, detail="")

    return payload


@app.get("/auth/check/{username}&{email}", status_code=200)
async def duplicated_user_check(username: str, email: str, db: Session = Depends(get_db)):
    return exist_by_username_and_email(username, email, db)


@app.post("/auth/login", status_code=201, response_model=schemas.Tokens)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db),
          rdb: Redis = Depends(get_redis)):
    user = authenticate_user(form_data.username, form_data.password, db)

    return create_tokens(user.username, rdb)


def get_current_user(token: str, db: Session):
    payload = validation_token(token)

    return select_user_by_username(payload.get("sub"), db)


@app.get('/user/me', status_code=200, response_model=schemas.UserDto)
def get_me(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    return get_current_user(token, db).to_dto()


@app.post("/auth", status_code=201, response_model=schemas.UserDto)
def sign_up(request: schemas.CreateUser, db: Session = Depends(get_db)):
    if not exist_by_username_and_email(request.username, request.email, db):
        return create_user(db, request).to_dto()

    raise HTTPException(status_code=409, detail="Duplicated user")


@app.post("/auth/reissue", status_code=201, response_model=schemas.Tokens)
def re_issue(request: schemas.ReIssue, db: Session = Depends(get_db), rdb: Redis = Depends(get_redis)):
    try:
        sub = jwt.decode(request.access_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]).get('sub')
    except JWTError:
        raise HTTPException(
            status_code=401,
            detail="Invalid token exception",
        )

    selected: bytes = select_redis(sub, rdb)

    if selected is None or selected.decode('utf-8') != request.refresh_token:

        raise HTTPException(
            status_code=401,
            detail="Invalid token exception",
        )

    delete_redis(sub, rdb)

    if not exist_by_username(sub, db):
        raise HTTPException(status_code=404, detail='User not found exception')

    return create_tokens(sub, rdb)
