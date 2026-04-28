"""Re-enrich all endpoints in the database.

Runs the full enrichment pipeline (including the new live probe) on every
endpoint, regardless of current risk_score.

Usage:
    cd backend && python -m scripts.reenrich
"""

import asyncio
import logging
import sys

# Ensure the backend package is importable
sys.path.insert(0, ".")

from app.database import get_database, close_client
from app.services.enrichment import enrich_endpoint

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s — %(message)s",
)
logger = logging.getLogger("reenrich")


async def main() -> None:
    db = get_database()
    collection = db["endpoints"]

    total = await collection.count_documents({})
    logger.info("Found %d endpoints to re-enrich", total)

    if total == 0:
        logger.info("Nothing to do.")
        return

    enriched = 0
    errors = 0
    cursor = collection.find({})

    async for doc in cursor:
        ep_id = doc["_id"]
        protocol = doc.get("protocol", "unknown")
        ip = doc.get("ip", "?")
        port = doc.get("port", "?")

        try:
            updated = await enrich_endpoint(db, ep_id)
            enriched += 1

            new_score = updated.get("risk_score", 0)
            new_auth = updated.get("auth_status", "unknown")
            new_model = updated.get("model", "")
            new_tools = len(updated.get("tools", []))
            new_tags = updated.get("tags", [])

            logger.info(
                "[%d/%d] %s:%s (%s) → risk=%.1f auth=%s model=%s tools=%d tags=%s",
                enriched + errors, total,
                ip, port, protocol,
                new_score, new_auth, new_model or "-", new_tools,
                new_tags[:5] if new_tags else "[]",
            )
        except Exception:
            errors += 1
            logger.exception("Failed to enrich %s (%s:%s)", ep_id, ip, port)

    logger.info(
        "Done. %d enriched, %d errors out of %d total",
        enriched, errors, total,
    )

    await close_client()


if __name__ == "__main__":
    asyncio.run(main())
