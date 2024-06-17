import contextlib
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlalchemy.orm import declarative_base
from src.config.settings import settings

Base = declarative_base()
DATABASE_URL = settings.DATABASE_URL

engine: AsyncEngine = create_async_engine(DATABASE_URL, echo=True)
SessionLocal = async_sessionmaker(autoflush=False, autocommit=False, bind=engine)


class DatabaseSessionManager:
    def __init__(self, url: str):
        self._engine: AsyncEngine = create_async_engine(url)
        self._session_maker: async_sessionmaker = async_sessionmaker(autoflush=False, autocommit=False, bind=self._engine)

    @contextlib.asynccontextmanager
    async def session(self):
        session = self._session_maker()
        try:
            yield session
            await session.commit()
        except Exception as err:
            print(err)
            await session.rollback()
            raise
        finally:
            await session.close()

sessionmanager = DatabaseSessionManager(settings.DATABASE_URL)

async def get_db():
    async with SessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
