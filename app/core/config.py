from functools import lru_cache

from pydantic.v1 import BaseSettings


class Settings(BaseSettings):
    DB_HOST: str
    DB_PORT: int
    DB_NAME: str
    DB_USER: str
    DB_PASSWORD: str
    SERVER_PORT: int
    SERVER_HOST: str
    MYSQL_ROOT_PASSWORD: str
    SECRET_KEY: str
    ALGORITHM: str
    ACCESS_TOKEN_EXP: int
    REFRESH_TOKEN_EXP: int
    REDIS_HOST: str
    REDIS_PORT: int
    REDIS_DB_NAME: str

    class Config:
        env_file = ".env"


@lru_cache()
def get_setting():
    return Settings()
