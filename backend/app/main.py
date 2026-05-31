"""AIMap FastAPI application."""

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.auth import get_current_user
from app.config import settings
from app.database import init_indexes, close_client
from app.limiter import limiter
from app.services.redis_client import close_redis
from app.routes import endpoints, scans, ranges, analyses, attack


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle."""
    await init_indexes()
    yield
    await close_redis()
    await close_client()


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="AIMap API",
    description="nmap for the Agentic Era -- discover, fingerprint, and exploit exposed AI agents.",
    version="0.1.0",
    lifespan=lifespan,
)

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS -- configurable via CORS_ORIGINS env var (comma-separated list or "*")
origins = (
    [o.strip() for o in settings.CORS_ORIGINS.split(",")]
    if settings.CORS_ORIGINS != "*"
    else ["*"]
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=origins != ["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Include routers
# ---------------------------------------------------------------------------

_auth = [Depends(get_current_user)]

app.include_router(endpoints.router, prefix="/api", dependencies=_auth)
app.include_router(scans.router, prefix="/api", dependencies=_auth)
app.include_router(ranges.router, prefix="/api", dependencies=_auth)
app.include_router(analyses.router, prefix="/api", dependencies=_auth)
app.include_router(attack.router, prefix="/api")  # auth handled per-route; WS can't use headers


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok", "service": "aimap-api"}


@app.get("/api/system/status")
async def system_status():
    """System concurrency status for monitoring."""
    from app.services.concurrency import get_concurrency_status

    return await get_concurrency_status()
