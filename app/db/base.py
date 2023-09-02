import uuid

from fastapi import HTTPException
from pymysql.err import IntegrityError
from pyotp import random_base32
from sqlalchemy.exc import NoResultFound
from sqlalchemy.orm import Session
from redis import StrictRedis, Redis

from app.model import models, schemas
from .session import sessionLocal
from ..core.config import get_setting
from ..security.security import pwd_context

settings = get_setting()


def get_redis():
    db = StrictRedis(host=settings.REDIS_HOST, port=settings.REDIS_PORT, db=settings.REDIS_DB_NAME, charset="utf-8")
    yield db

    db.close()


def get_db():
    db = sessionLocal()
    try:
        yield db
    except:
        db.rollback()
    finally:
        db.close()


def create_user(db: Session, user: schemas.CreateUser):
    user = models.User(
        id=uuid.uuid4().bytes,
        email=user.email,
        username=user.username,
        full_name=user.full_name,
        hashed_password=pwd_context.hash(user.password),
        otp_secret=random_base32(),
        role=user.role
    )
    db.add(user)
    db.commit()
    try:
        db.refresh(user)
    except IntegrityError:
        raise HTTPException(status_code=409, detail="Duplicated user")
    return user


def select_user_by_username(username: str, db: Session):

    try:
        user = db.query(models.User).filter_by(username=username, disabled=False).one()
    except NoResultFound:
        raise HTTPException(status_code=404, detail='Not found user exception')

    return user


def exist_by_username_and_email(username: str, email: str, db: Session):

    r1 = db.query(models.User).filter_by(email=email).first()
    r2 = db.query(models.User).filter_by(username=username).first()

    if r1 is None and r2 is None:
        return False

    return True


def exist_by_username(username: str, db: Session):

    if db.query(models.User).filter_by(username=username).first() is None:
        return False

    return True


def create_redis(key: str, value: str, db: Redis):
    db.set(name=key, value=value, ex=settings.REFRESH_TOKEN_EXP * 60)


def select_redis(key: str, db: Redis):
    return db.get(key)


def delete_redis(key: str, db: Redis):
    db.delete(key)

