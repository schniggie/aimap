"""Scan Management routes."""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from starlette.requests import Request

from app.auth import get_current_user, _get_jwks_client
from app.config import settings
from app.database import get_database
from app.limiter import limiter
from app.discovery.orchestrator import ScanOrchestrator
from app.discovery.nuclei_runner import NucleiRunner
from app.discovery.shodan_adapter import AGENT_QUERIES, QUERY_DESCRIPTIONS
from app.services.concurrency import acquire_slot, release_slot
from app.services.enrichment import enrich_endpoint

router = APIRouter(prefix="/scans", tags=["scans"])
logger = logging.getLogger(__name__)

# Keep track of active scan tasks so they can be cancelled
_active_scan_tasks: dict[str, asyncio.Task] = {}


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class PaginatedScans(BaseModel):
    items: list[dict[str, Any]]
    total: int
    page: int
    page_size: int


class StatusUpdate(BaseModel):
    status: str  # "paused", "running", "stopped"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _serialize(doc: dict) -> dict:
    if not doc:
        return doc
    out = {k: v for k, v in doc.items() if k != "_id"}
    if "_id" in doc:
        out["id"] = str(doc["_id"])
    return out


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/query-presets")
async def list_query_presets() -> dict[str, Any]:
    """Return the available predefined Shodan query presets.

    Used by the frontend to populate the ingestion scan form.
    """
    presets = []
    for key, query in AGENT_QUERIES.items():
        presets.append({
            "key": key,
            "query": query,
            "description": QUERY_DESCRIPTIONS.get(key, key),
        })
    return {"presets": presets}


@router.get("", response_model=PaginatedScans)
async def list_scans(
    status: str | None = None,
    scan_type: str | None = None,
    created_by: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
) -> PaginatedScans:
    """List scans with filters and pagination."""
    db = get_database()
    collection = db["scans"]

    query: dict[str, Any] = {}
    if status:
        query["status"] = status
    if scan_type:
        query["type"] = scan_type
    if created_by:
        query["created_by"] = created_by

    skip = (page - 1) * page_size
    total = await collection.count_documents(query)
    cursor = collection.find(query).sort("created_at", -1).skip(skip).limit(page_size)
    items = [_serialize(doc) async for doc in cursor]

    return PaginatedScans(items=items, total=total, page=page, page_size=page_size)


@router.get("/{scan_id}")
async def get_scan(scan_id: str) -> dict[str, Any]:
    """Get scan details."""
    db = get_database()
    collection = db["scans"]
    doc = await collection.find_one({"_id": scan_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _serialize(doc)


@router.post("", status_code=201)
async def create_scan(body: dict[str, Any], user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Create a new scan."""
    db = get_database()
    collection = db["scans"]

    now = datetime.now(timezone.utc).isoformat()
    body["created_by"] = user["user_id"]
    body.setdefault("status", "queued")
    body.setdefault("created_at", now)
    body.setdefault("updated_at", now)
    body.setdefault("progress", {
        "total_hosts": 0,
        "scanned": 0,
        "alive": 0,
        "agents_found": 0,
        "percent_complete": 0.0,
    })
    body.setdefault("results_summary", {
        "total_endpoints": 0,
        "by_protocol": {},
        "by_risk": {},
        "no_auth_count": 0,
    })
    body.setdefault("endpoint_ids", [])

    if "_id" not in body:
        body["_id"] = f"scan_{uuid.uuid4().hex[:12]}"

    await collection.insert_one(body)
    return _serialize(body)


@router.put("/{scan_id}/status")
async def update_scan_status(scan_id: str, body: StatusUpdate) -> dict[str, Any]:
    """Update scan status (pause/resume/stop)."""
    db = get_database()
    collection = db["scans"]

    valid_statuses = {"paused", "running", "stopped", "queued", "completed", "failed"}
    if body.status not in valid_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Must be one of: {', '.join(sorted(valid_statuses))}",
        )

    now = datetime.now(timezone.utc).isoformat()
    result = await collection.find_one_and_update(
        {"_id": scan_id},
        {"$set": {"status": body.status, "updated_at": now}},
        return_document=True,
    )
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _serialize(result)


@router.delete("/{scan_id}", status_code=204)
async def delete_scan(scan_id: str, user: dict = Depends(get_current_user)) -> None:
    """Delete a scan."""
    db = get_database()
    collection = db["scans"]
    result = await collection.delete_one({"_id": scan_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Scan not found")


# ---------------------------------------------------------------------------
# Scan execution
# ---------------------------------------------------------------------------

@router.post("/{scan_id}/run")
@limiter.limit("10/minute")
async def run_scan(request: Request, scan_id: str, user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Trigger execution of a queued scan in the background.

    The scan runs as a background asyncio task. Progress can be monitored
    via the WebSocket at /ws/scans/{scan_id}/progress or by polling
    GET /api/scans/{scan_id}.
    """
    db = get_database()
    collection = db["scans"]

    doc = await collection.find_one({"_id": scan_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")

    if doc.get("status") == "running":
        raise HTTPException(status_code=409, detail="Scan is already running")

    # Mark as running
    now = datetime.now(timezone.utc).isoformat()
    await collection.update_one(
        {"_id": scan_id},
        {"$set": {"status": "running", "updated_at": now}},
    )

    # Try Modal serverless dispatch
    modal_dispatched = False
    if settings.MODAL_ENABLED:
        try:
            import modal

            fn = modal.Function.from_name("aimap", "run_scan_task")
            fn.spawn(scan_id=scan_id, scan_doc=doc)
            modal_dispatched = True
            logger.info("Scan %s dispatched to Modal", scan_id)
        except Exception:
            logger.warning(
                "Modal dispatch failed for scan %s, falling back to local", scan_id
            )

    if not modal_dispatched:
        # Local execution with concurrency control
        slot = await acquire_slot("scan")
        if not slot:
            raise HTTPException(
                status_code=429,
                detail="Too many concurrent scans. Please wait and try again.",
            )
        task = asyncio.create_task(_execute_scan(scan_id, doc))
        _active_scan_tasks[scan_id] = task
        task.add_done_callback(lambda t: _active_scan_tasks.pop(scan_id, None))

    return {"id": scan_id, "status": "running", "message": "Scan started"}


async def _execute_scan(scan_id: str, scan_doc: dict) -> None:
    """Background coroutine that runs the actual scan pipeline."""
    db = get_database()
    collection = db["scans"]

    async def progress_callback(update: dict) -> None:
        """Persist progress to the scan document."""
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
        # Build scan config from stored document
        config = scan_doc.get("config", {})
        scan_type = config.get("type", "active")
        scan_config = {
            "type": scan_type,
            "scan_id": scan_id,
            **config,
        }

        nuclei = NucleiRunner()
        if not nuclei.check_nuclei():
            logger.warning("Nuclei not found, scan will skip active probing")

        orchestrator = ScanOrchestrator(nuclei_runner=nuclei)
        result = await orchestrator.run_scan(scan_config, db, progress_callback)

        # Enrich all discovered endpoints (risk scoring, framework detection, etc.)
        endpoint_ids = result.get("endpoint_ids", [])
        if endpoint_ids:
            if progress_callback:
                await progress_callback({
                    "phase": "enrichment",
                    "status": "started",
                    "endpoint_count": len(endpoint_ids),
                })
            enriched = 0
            for ep_id in set(endpoint_ids):  # deduplicate
                try:
                    await enrich_endpoint(db, ep_id)
                    enriched += 1
                except Exception:
                    logger.warning("Failed to enrich endpoint %s", ep_id, exc_info=True)
            logger.info("Enriched %d/%d endpoints for scan %s", enriched, len(endpoint_ids), scan_id)
            if progress_callback:
                await progress_callback({
                    "phase": "enrichment",
                    "status": "completed",
                    "enriched_count": enriched,
                })

        # Update scan as completed
        now = datetime.now(timezone.utc).isoformat()
        await collection.update_one(
            {"_id": scan_id},
            {"$set": {
                "status": "completed",
                "updated_at": now,
                "completed_at": now,
                "progress.percent_complete": 100.0,
                "results_summary.total_endpoints": result.get("total_endpoints", 0),
                "endpoint_ids": result.get("endpoint_ids", []),
            }},
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
        await release_slot("scan")


# ---------------------------------------------------------------------------
# WebSocket for live scan progress
# ---------------------------------------------------------------------------

@router.websocket("/{scan_id}/progress")
async def scan_progress_ws(websocket: WebSocket, scan_id: str, token: str | None = None) -> None:
    """Stream scan progress updates over WebSocket.

    Polls the scan document every 2 seconds and pushes updates.
    """
    # Authenticate via token query parameter (skip in local dev mode)
    if settings.CLERK_ISSUER:
        if not token:
            await websocket.close(code=1008, reason="Authentication required")
            return
        client = _get_jwks_client()
        try:
            import jwt as _jwt
            signing_key = client.get_signing_key_from_jwt(token)
            _jwt.decode(token, signing_key.key, algorithms=["RS256"], issuer=settings.CLERK_ISSUER)
        except Exception:
            await websocket.close(code=1008, reason="Invalid token")
            return

    await websocket.accept()
    db = get_database()
    collection = db["scans"]

    try:
        last_update = None
        while True:
            doc = await collection.find_one({"_id": scan_id})
            if not doc:
                await websocket.send_json({"error": "Scan not found"})
                break

            current = {
                "id": scan_id,
                "status": doc.get("status"),
                "progress": doc.get("progress", {}),
                "last_progress": doc.get("last_progress"),
            }

            if current != last_update:
                await websocket.send_json(current)
                last_update = current

            if doc.get("status") in ("completed", "failed", "stopped"):
                await websocket.send_json({"status": doc["status"], "final": True})
                break

            await asyncio.sleep(2)

    except WebSocketDisconnect:
        pass
    except Exception:
        logger.exception("WebSocket error for scan %s", scan_id)
