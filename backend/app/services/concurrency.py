"""Concurrency control for scans and attacks.

Uses Redis counters for cross-worker visibility when Redis is available,
falling back to process-local asyncio.Semaphores for local dev.

Limits:
- MAX_CONCURRENT_SCANS  = 3
- MAX_CONCURRENT_ATTACKS = 5
"""

import asyncio
import logging
from typing import Literal

from app.services.redis_client import get_redis

logger = logging.getLogger(__name__)

MAX_CONCURRENT_SCANS = 3
MAX_CONCURRENT_ATTACKS = 5

_REDIS_KEY_SCANS = "aimap:active_scans"
_REDIS_KEY_ATTACKS = "aimap:active_attacks"

# Process-local fallback semaphores
_scan_semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)
_attack_semaphore = asyncio.Semaphore(MAX_CONCURRENT_ATTACKS)


async def acquire_slot(kind: Literal["scan", "attack"]) -> bool:
    """Try to acquire a concurrency slot. Returns False if at capacity.

    Uses Redis INCR for distributed counting when available, otherwise
    falls back to a local asyncio.Semaphore (non-blocking try-acquire).
    """
    if kind == "scan":
        redis_key = _REDIS_KEY_SCANS
        max_val = MAX_CONCURRENT_SCANS
        semaphore = _scan_semaphore
    else:
        redis_key = _REDIS_KEY_ATTACKS
        max_val = MAX_CONCURRENT_ATTACKS
        semaphore = _attack_semaphore

    r = await get_redis()

    if r is not None:
        count = await r.incr(redis_key)
        if count > max_val:
            await r.decr(redis_key)
            logger.warning(
                "Concurrency limit reached for %s (%d/%d)", kind, count - 1, max_val
            )
            return False
        # Set a TTL on the key so it doesn't persist forever if the app crashes
        await r.expire(redis_key, 3600)
        return True
    else:
        # Local fallback: try to acquire without blocking
        acquired = semaphore._value > 0
        if acquired:
            await semaphore.acquire()
        return acquired


async def release_slot(kind: Literal["scan", "attack"]) -> None:
    """Release a concurrency slot."""
    if kind == "scan":
        redis_key = _REDIS_KEY_SCANS
        semaphore = _scan_semaphore
    else:
        redis_key = _REDIS_KEY_ATTACKS
        semaphore = _attack_semaphore

    r = await get_redis()

    if r is not None:
        count = await r.decr(redis_key)
        # Guard against going negative (e.g. after a crash/restart)
        if count < 0:
            await r.set(redis_key, 0)
    else:
        semaphore.release()


async def get_concurrency_status() -> dict:
    """Return current concurrency counts for monitoring."""
    r = await get_redis()

    if r is not None:
        active_scans = int(await r.get(_REDIS_KEY_SCANS) or 0)
        active_attacks = int(await r.get(_REDIS_KEY_ATTACKS) or 0)
    else:
        active_scans = MAX_CONCURRENT_SCANS - _scan_semaphore._value
        active_attacks = MAX_CONCURRENT_ATTACKS - _attack_semaphore._value

    return {
        "active_scans": max(active_scans, 0),
        "max_scans": MAX_CONCURRENT_SCANS,
        "active_attacks": max(active_attacks, 0),
        "max_attacks": MAX_CONCURRENT_ATTACKS,
    }
