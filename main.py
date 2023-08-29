import uvicorn

from app.core.config import get_setting

settings = get_setting()

if __name__ == '__main__':
    uvicorn.run("app.app:app", host=settings.SERVER_HOST, port=settings.SERVER_PORT, reload=True)
