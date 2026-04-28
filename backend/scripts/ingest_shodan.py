#!/usr/bin/env python3
"""Shodan ingestion script — pulls exposed AI agent endpoints into MongoDB.

Usage:
    cd backend && source .venv/bin/activate
    python scripts/ingest_shodan.py [--max-per-query 50] [--queries mcp,openai_compat]
"""

import argparse
import asyncio
import logging
import sys

from motor.motor_asyncio import AsyncIOMotorClient

# Add parent dir to path so we can import app modules
sys.path.insert(0, ".")

from app.config import settings
from app.database import init_indexes, set_database
from app.discovery.shodan_adapter import ShodanAdapter, AGENT_QUERIES

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("ingest_shodan")


async def main(max_per_query: int, query_keys: list[str] | None):
    # Connect to MongoDB
    client = AsyncIOMotorClient(settings.MONGODB_URI)
    db = client[settings.MONGODB_DB]
    set_database(db)

    # Ensure indexes exist
    await init_indexes()

    # Create adapter
    adapter = ShodanAdapter()

    queries_to_run = {k: v for k, v in AGENT_QUERIES.items()
                      if query_keys is None or k in query_keys}

    logger.info("Starting Shodan ingestion with %d queries, max %d results each",
                len(queries_to_run), max_per_query)

    total_ingested = 0

    for query_name, query_str in queries_to_run.items():
        logger.info("--- Query: %s -> %s ---", query_name, query_str)
        try:
            endpoint_ids = await adapter.ingest(
                query=query_str,
                max_results=max_per_query,
                db=db,
            )
            logger.info("  Ingested %d endpoints from query '%s'",
                        len(endpoint_ids), query_name)
            total_ingested += len(endpoint_ids)
        except Exception:
            logger.exception("  Error during query '%s'", query_name)

    # Print summary
    total_in_db = await db.endpoints.count_documents({})
    logger.info("=== Ingestion complete ===")
    logger.info("  New/updated endpoints this run: %d", total_ingested)
    logger.info("  Total endpoints in database: %d", total_in_db)

    # Print protocol breakdown
    pipeline = [
        {"$group": {"_id": "$protocol", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]
    async for doc in db.endpoints.aggregate(pipeline):
        logger.info("  %s: %d", doc["_id"], doc["count"])

    client.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ingest Shodan data into AIMap")
    parser.add_argument("--max-per-query", type=int, default=50,
                        help="Max results per search query (default: 50)")
    parser.add_argument("--queries", type=str, default=None,
                        help="Comma-separated query keys to run (default: all)")
    args = parser.parse_args()

    query_keys = args.queries.split(",") if args.queries else None

    asyncio.run(main(args.max_per_query, query_keys))
