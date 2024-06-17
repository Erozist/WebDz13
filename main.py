import redis.asyncio as redis
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi_limiter import FastAPILimiter

from src.config.settings import settings
from src.database.db import engine, Base
from src.routes import contacts, auth

app = FastAPI()

origins = [
    "http://localhost",
    "http://localhost:8000",
    "http://yourdomain.com"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup():
    redis_client = redis.from_url(f"redis://{settings.redis_host}:{settings.redis_port}")
    await FastAPILimiter.init(redis_client)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


app.include_router(auth.router)
app.include_router(contacts.router)
