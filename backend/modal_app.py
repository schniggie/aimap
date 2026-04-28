"""Modal serverless functions for AIMap.

Dispatches attack and scan tasks to Modal's serverless infrastructure,
enabling horizontal scaling without local concurrency limits.

Deploy:
    cd backend && modal deploy modal_app.py

Secret (create once):
    modal secret create aimap-secrets \
        MONGODB_URI=<your-mongo-uri> \
        REDIS_URL=<your-redis-uri> \
        MONGODB_DB=aimap \
        SHODAN_API_KEY=<key> \
        ANTHROPIC_API_KEY=<key>
"""

import modal

app = modal.App("aimap")

image = (
    modal.Image.debian_slim(python_version="3.12")
    .pip_install_from_requirements("requirements.txt")
    .apt_install("wget", "unzip")
    .run_commands(
        # ProjectDiscovery nuclei
        "wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip -O /tmp/nuclei.zip"
        " && unzip /tmp/nuclei.zip -d /usr/local/bin/"
        " && chmod +x /usr/local/bin/nuclei"
        " && rm /tmp/nuclei.zip",
        # ProjectDiscovery httpx
        "wget -q https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_linux_amd64.zip -O /tmp/httpx.zip"
        " && unzip /tmp/httpx.zip -d /usr/local/bin/"
        " && chmod +x /usr/local/bin/httpx"
        " && rm /tmp/httpx.zip",
    )
)

secrets = [modal.Secret.from_name("aimap-secrets")]
code_mounts = [
    modal.Mount.from_local_dir("app", remote_path="/root/app"),
    modal.Mount.from_local_dir("templates", remote_path="/root/templates"),
]


def _setup_path():
    """Ensure the app package is importable inside the Modal container."""
    import sys

    if "/root" not in sys.path:
        sys.path.insert(0, "/root")


# ---------------------------------------------------------------------------
# Attack task
# ---------------------------------------------------------------------------

@app.function(
    image=image,
    mounts=code_mounts,
    secrets=secrets,
    timeout=600,
)
async def run_attack_task(
    attack_id: str,
    endpoint_id: str,
    target_url: str,
    protocol: str,
    techniques: list[str],
    max_steps: int,
    depth: str,
) -> None:
    """Run an attack in a serverless Modal container.

    Writes log entries to Redis Streams and persists results to MongoDB.
    The FastAPI backend streams from Redis via WebSocket as usual.
    """
    _setup_path()

    import json
    import logging
    import os
    import uuid
    from datetime import datetime, timezone

    import motor.motor_asyncio
    import redis.asyncio as aioredis

    logger = logging.getLogger("modal.attack")

    mongo_client = motor.motor_asyncio.AsyncIOMotorClient(os.environ["MONGODB_URI"])
    db = mongo_client[os.environ.get("MONGODB_DB", "aimap")]
    r = aioredis.from_url(os.environ["REDIS_URL"], decode_responses=True)

    stream_key = f"attack:{attack_id}:logs"
    status_key = f"attack:{attack_id}:status"

    try:
        engine_kwargs = dict(
            target_url=target_url,
            techniques=techniques,
            max_steps=max_steps,
            depth=depth,
        )

        if protocol == "ollama":
            from app.services.attack_ollama import OllamaAttackEngine

            engine = OllamaAttackEngine(**engine_kwargs)
        elif protocol == "openclaw":
            from app.services.attack_openclaw import OpenClawAttackEngine

            engine = OpenClawAttackEngine(**engine_kwargs)
        else:
            from app.services.attack_mcp import MCPAttackEngine

            engine = MCPAttackEngine(**engine_kwargs)

        async for entry in engine.run():
            await r.xadd(stream_key, {"data": json.dumps(entry)}, maxlen=5000)

        # Persist results to analysis document
        testing_info = engine.build_testing_info()
        now = datetime.now(timezone.utc).isoformat()

        await db["analyses"].update_one(
            {"endpoint_id": endpoint_id},
            {
                "$set": {"testing": testing_info, "updated_at": now},
                "$setOnInsert": {
                    "_id": f"an_{uuid.uuid4().hex[:12]}",
                    "endpoint_id": endpoint_id,
                    "created_at": now,
                },
            },
            upsert=True,
        )

        # Bump risk score for critical/high findings
        critical = sum(
            1 for x in engine.results if x.success and x.severity == "critical"
        )
        high = sum(
            1 for x in engine.results if x.success and x.severity == "high"
        )

        if critical > 0 or high > 0:
            risk_bump = min(critical * 1.5 + high * 0.8, 4.0)
            ep = await db["endpoints"].find_one({"_id": endpoint_id})
            if ep:
                new_risk = min(ep.get("risk_score", 5.0) + risk_bump, 10.0)
                factors = ep.get("risk_factors", [])
                if critical > 0 and "critical_vulns_confirmed" not in factors:
                    factors.append("critical_vulns_confirmed")
                if high > 0 and "high_vulns_confirmed" not in factors:
                    factors.append("high_vulns_confirmed")
                await db["endpoints"].update_one(
                    {"_id": endpoint_id},
                    {
                        "$set": {
                            "risk_score": new_risk,
                            "risk_factors": factors,
                            "updated_at": now,
                        }
                    },
                )

        logger.info(
            "Attack %s completed: %d findings (%d critical, %d high)",
            attack_id,
            len(engine.results),
            critical,
            high,
        )

    except Exception as exc:
        logger.exception("Attack %s failed", attack_id)
        now = datetime.now(timezone.utc).isoformat()
        await db["analyses"].update_one(
            {"endpoint_id": endpoint_id},
            {"$set": {"testing.status": "failed", "updated_at": now}},
        )
        await r.xadd(
            stream_key,
            {
                "data": json.dumps(
                    {
                        "type": "REASONING",
                        "content": f"Attack failed: {exc}",
                        "severity": "info",
                        "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                    }
                )
            },
            maxlen=5000,
        )

    finally:
        await r.set(status_key, "completed", ex=3600)
        await r.aclose()
        mongo_client.close()


# ---------------------------------------------------------------------------
# Scan task
# ---------------------------------------------------------------------------

@app.function(
    image=image,
    mounts=code_mounts,
    secrets=secrets,
    timeout=1800,
)
async def run_scan_task(
    scan_id: str,
    scan_doc: dict,
) -> None:
    """Run a scan pipeline in a serverless Modal container.

    Progress updates are written to MongoDB, readable via WebSocket polling.
    """
    _setup_path()

    import logging
    import os
    from datetime import datetime, timezone
    from typing import Any

    import motor.motor_asyncio

    logger = logging.getLogger("modal.scan")

    mongo_client = motor.motor_asyncio.AsyncIOMotorClient(os.environ["MONGODB_URI"])
    db = mongo_client[os.environ.get("MONGODB_DB", "aimap")]
    collection = db["scans"]

    async def progress_callback(update: dict) -> None:
        now = datetime.now(timezone.utc).isoformat()
        sets: dict[str, Any] = {"updated_at": now}
        phase = update.get("phase", "")
        status = update.get("status", "")

        if phase == "httpx" and status == "completed":
            sets["progress.alive"] = update.get("alive_count", 0)
        elif phase == "nuclei" and status == "completed":
            sets["progress.agents_found"] = update.get("findings_count", 0)
        elif phase == "ingestion" and status == "completed":
            sets["progress.agents_found"] = update.get("endpoints_found", 0)
        elif phase == "complete":
            sets["progress.percent_complete"] = 100.0

        sets["last_progress"] = update
        await collection.update_one({"_id": scan_id}, {"$set": sets})

    try:
        from app.discovery.nuclei_runner import NucleiRunner
        from app.discovery.orchestrator import ScanOrchestrator
        from app.services.enrichment import enrich_endpoint

        config = scan_doc.get("config", {})
        scan_config = {
            "type": config.get("type", "active"),
            "scan_id": scan_id,
            **config,
        }

        nuclei = NucleiRunner()
        if not nuclei.check_nuclei():
            logger.warning("Nuclei not found in Modal container")

        orchestrator = ScanOrchestrator(nuclei_runner=nuclei)
        result = await orchestrator.run_scan(scan_config, db, progress_callback)

        # Enrich discovered endpoints
        endpoint_ids = result.get("endpoint_ids", [])
        if endpoint_ids:
            await progress_callback(
                {
                    "phase": "enrichment",
                    "status": "started",
                    "endpoint_count": len(endpoint_ids),
                }
            )
            enriched = 0
            for ep_id in set(endpoint_ids):
                try:
                    await enrich_endpoint(db, ep_id)
                    enriched += 1
                except Exception:
                    logger.warning(
                        "Failed to enrich endpoint %s", ep_id, exc_info=True
                    )
            await progress_callback(
                {
                    "phase": "enrichment",
                    "status": "completed",
                    "enriched_count": enriched,
                }
            )

        # Mark scan as completed
        now = datetime.now(timezone.utc).isoformat()
        await collection.update_one(
            {"_id": scan_id},
            {
                "$set": {
                    "status": "completed",
                    "updated_at": now,
                    "completed_at": now,
                    "progress.percent_complete": 100.0,
                    "results_summary.total_endpoints": result.get(
                        "total_endpoints", 0
                    ),
                    "endpoint_ids": result.get("endpoint_ids", []),
                }
            },
        )
        logger.info("Scan %s completed: %s", scan_id, result)

    except Exception:
        logger.exception("Scan %s failed", scan_id)
        now = datetime.now(timezone.utc).isoformat()
        await collection.update_one(
            {"_id": scan_id},
            {"$set": {"status": "failed", "updated_at": now}},
        )

    finally:
        mongo_client.close()
