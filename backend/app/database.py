"""Async MongoDB connection and index management using motor."""

import logging

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo import ASCENDING, DESCENDING, TEXT

from app.config import settings

logger = logging.getLogger(__name__)

_client: AsyncIOMotorClient | None = None
_db: AsyncIOMotorDatabase | None = None


def get_client() -> AsyncIOMotorClient:
    """Return a singleton motor client."""
    global _client
    if _client is None:
        _client = AsyncIOMotorClient(settings.MONGODB_URI)
    return _client


def get_database() -> AsyncIOMotorDatabase:
    """Return the configured motor database."""
    global _db
    if _db is None:
        _db = get_client()[settings.MONGODB_DB]
    return _db


def set_database(db: AsyncIOMotorDatabase) -> None:
    """Override the database instance (used for testing)."""
    global _db
    _db = db


async def init_indexes() -> None:
    """Create all required indexes on startup.

    Safe to call repeatedly -- MongoDB treats index creation as idempotent.
    """
    db = get_database()

    # ── endpoints ────────────────────────────────────────────────
    endpoints = db["endpoints"]

    await endpoints.create_index(
        [("ip", ASCENDING), ("port", ASCENDING), ("protocol", ASCENDING)],
        unique=True,
        name="ip_port_protocol_unique",
    )
    await endpoints.create_index(
        [("risk_score", DESCENDING)],
        name="risk_score_desc",
    )
    await endpoints.create_index(
        [("protocol", ASCENDING), ("auth_status", ASCENDING)],
        name="protocol_auth",
    )
    await endpoints.create_index(
        [("geo.country_code", ASCENDING)],
        name="geo_country",
    )
    await endpoints.create_index(
        [("tools.name", ASCENDING)],
        name="tools_name",
    )
    await endpoints.create_index(
        [("range_id", ASCENDING)],
        name="range_id",
    )
    await endpoints.create_index(
        [("tags", ASCENDING)],
        name="tags",
    )
    await endpoints.create_index(
        [("first_seen", DESCENDING)],
        name="first_seen_desc",
    )

    # Text index -- may not be supported by all mock backends
    try:
        await endpoints.create_index(
            [
                ("hostname", TEXT),
                ("tools.name", TEXT),
                ("tools.description", TEXT),
                ("system_prompt", TEXT),
            ],
            name="text_search",
        )
    except Exception:
        logger.warning("Text index creation skipped (unsupported backend)")

    # ── analyses ─────────────────────────────────────────────────
    analyses = db["analyses"]

    await analyses.create_index(
        [("endpoint_id", ASCENDING)],
        unique=True,
        name="endpoint_id_unique",
    )
    await analyses.create_index(
        [("testing.status", ASCENDING)],
        name="testing_status",
    )

    # ── scans ────────────────────────────────────────────────────
    scans = db["scans"]

    await scans.create_index(
        [("status", ASCENDING), ("created_at", DESCENDING)],
        name="status_created",
    )
    await scans.create_index(
        [("created_by", ASCENDING)],
        name="created_by",
    )
    await scans.create_index(
        [("config.range_id", ASCENDING)],
        name="config_range_id",
    )

    # ── ranges ───────────────────────────────────────────────────
    ranges = db["ranges"]

    await ranges.create_index(
        [("cidr", ASCENDING)],
        name="cidr",
    )
    await ranges.create_index(
        [("created_by", ASCENDING)],
        name="ranges_created_by",
    )
    await ranges.create_index(
        [("monitoring.next_scan_at", ASCENDING)],
        name="monitoring_next_scan",
    )


async def close_client() -> None:
    """Close the motor client connection."""
    global _client, _db
    if _client is not None:
        _client.close()
        _client = None
        _db = None
