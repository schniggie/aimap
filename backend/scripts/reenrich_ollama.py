"""Re-enrich only Ollama endpoints (and unknown-protocol endpoints on port 11434).

Usage:
    cd backend && .venv/bin/python -m scripts.reenrich_ollama
"""

import asyncio
import logging
import sys

sys.path.insert(0, ".")

from app.database import get_database, close_client
from app.services.enrichment import enrich_endpoint

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s — %(message)s",
)
logger = logging.getLogger("reenrich_ollama")


async def main() -> None:
    db = get_database()
    collection = db["endpoints"]

    # Find Ollama endpoints + unknown on port 11434 + openai_compat
    query = {
        "$or": [
            {"protocol": "ollama"},
            {"protocol": "unknown", "port": 11434},
            {"protocol": "openai_compat"},
        ]
    }

    total = await collection.count_documents(query)
    logger.info("Found %d Ollama / OpenAI-compat / unknown:11434 endpoints to re-enrich", total)

    if total == 0:
        logger.info("Nothing to do.")
        await close_client()
        return

    enriched = 0
    errors = 0
    cursor = collection.find(query)

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
            new_framework = updated.get("framework", "")

            logger.info(
                "[%d/%d] %s:%s (%s) → risk=%.1f auth=%s model=%s fw=%s tools=%d tags=%s",
                enriched + errors, total,
                ip, port, protocol,
                new_score, new_auth, new_model or "-", new_framework or "-",
                new_tools, new_tags[:5] if new_tags else "[]",
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
