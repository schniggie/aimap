"""Analysis & Testing routes."""

import asyncio
import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect

from app.database import get_database

router = APIRouter(prefix="/analyses", tags=["analyses"])


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

@router.get("/{endpoint_id}")
async def get_analysis(endpoint_id: str) -> dict[str, Any]:
    """Get analysis for an endpoint."""
    db = get_database()
    collection = db["analyses"]
    doc = await collection.find_one({"endpoint_id": endpoint_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return _serialize(doc)


@router.post("", status_code=201)
async def create_or_update_analysis(body: dict[str, Any]) -> dict[str, Any]:
    """Create or update an analysis."""
    db = get_database()
    collection = db["analyses"]

    endpoint_id = body.get("endpoint_id")
    if not endpoint_id:
        raise HTTPException(status_code=400, detail="endpoint_id is required")

    now = datetime.now(timezone.utc).isoformat()
    body.setdefault("created_at", now)
    body["updated_at"] = now

    # Upsert: create if not exists, update if exists
    existing = await collection.find_one({"endpoint_id": endpoint_id})
    if existing:
        body.pop("_id", None)
        body.pop("id", None)
        result = await collection.find_one_and_update(
            {"endpoint_id": endpoint_id},
            {"$set": body},
            return_document=True,
        )
        return _serialize(result)
    else:
        if "_id" not in body:
            import uuid
            body["_id"] = f"an_{uuid.uuid4().hex[:12]}"
        await collection.insert_one(body)
        return _serialize(body)


@router.get("/{endpoint_id}/testing")
async def get_test_results(endpoint_id: str) -> dict[str, Any]:
    """Get test results for an endpoint."""
    db = get_database()
    collection = db["analyses"]
    doc = await collection.find_one({"endpoint_id": endpoint_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Analysis not found")

    testing = doc.get("testing", {})
    return {
        "endpoint_id": endpoint_id,
        "testing": testing,
    }
