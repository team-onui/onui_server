from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.core.config import get_setting

settings = get_setting()

DATABASE_URL = 'mysql+pymysql://{}:{}@{}:{}/{}'.format(
    settings.DB_USER,
    settings.DB_PASSWORD,
    settings.DB_HOST,
    settings.DB_PORT,
    settings.DB_NAME
)

db_engine = create_engine(url=DATABASE_URL, pool_size=50, max_overflow=50, echo=False)

sessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=db_engine)
