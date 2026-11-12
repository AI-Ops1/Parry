from contextlib import asynccontextmanager
from fastapi import FastAPI
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_pool()
    yield
app = FastAPI(lifespan=lifespan)
