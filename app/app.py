from fastapi import FastAPI

from app.db.base import Base
from app.db.session import db_engine


def create_tables():
    Base.metadata.create_all(bind=db_engine)


def get_application():
    create_tables()
    return FastAPI()


@app.get('/', status_code=200)
def show_all_cloud_word():
    return {'message': 'HelloWorld'}