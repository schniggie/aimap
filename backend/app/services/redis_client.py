"""Async Redis connection for AIMap.

Provides a singleton async Redis client used by:
- Attack log streaming (Redis Streams)
- Concurrency control (Redis counters)

Falls back gracefully when Redis is unavailable (e.g. local dev without Docker),
allowing the app to run with in-memory fallbacks.
"""

import logging

import redis.asyncio as aioredis

from app.config import settings

logger = logging.getLogger(__name__)

_pool: aioredis.Redis | None = None
_unavailable: bool = False


async def get_redis() -> aioredis.Redis | None:
    """Return the shared async Redis connection, or None if unavailable.

    On first call, attempts to connect and ping Redis. If that fails,
    marks Redis as unavailable for the lifetime of the process so we
    don't retry on every request.
    """
    global _pool, _unavailable

    if _unavailable:
        return None

    if _pool is None:
        try:
            _pool = aioredis.from_url(
                settings.REDIS_URL,
                decode_responses=True,
                socket_connect_timeout=3,
            )
            await _pool.ping()
            logger.info("Redis connected: %s", settings.REDIS_URL)
        except Exception:
            logger.warning(
                "Redis unavailable at %s — falling back to in-memory state",
                settings.REDIS_URL,
            )
            _pool = None
            _unavailable = True
            return None

    return _pool


async def close_redis() -> None:
    """Close the Redis connection pool."""
    global _pool, _unavailable
    if _pool is not None:
        await _pool.aclose()
        _pool = None
    _unavailable = False
