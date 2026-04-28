"""IP Range Monitor routes."""

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.auth import get_current_user
from app.database import get_database

router = APIRouter(prefix="/ranges", tags=["ranges"])


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class PaginatedRanges(BaseModel):
    items: list[dict[str, Any]]
    total: int
    page: int
    page_size: int


class TriggerScanResponse(BaseModel):
    scan_id: str
    range_id: str
    status: str


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

@router.get("", response_model=PaginatedRanges)
async def list_ranges(
    created_by: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
) -> PaginatedRanges:
    """List monitored ranges."""
    db = get_database()
    collection = db["ranges"]

    query: dict[str, Any] = {}
    if created_by:
        query["created_by"] = created_by

    skip = (page - 1) * page_size
    total = await collection.count_documents(query)
    cursor = collection.find(query).sort("created_at", -1).skip(skip).limit(page_size)
    items = [_serialize(doc) async for doc in cursor]

    return PaginatedRanges(items=items, total=total, page=page, page_size=page_size)


@router.get("/{range_id}")
async def get_range(range_id: str) -> dict[str, Any]:
    """Get range details with stats."""
    db = get_database()
    collection = db["ranges"]
    doc = await collection.find_one({"_id": range_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Range not found")

    # Enrich with live endpoint count from endpoints collection
    endpoints_collection = db["endpoints"]
    endpoint_count = await endpoints_collection.count_documents({"range_id": range_id})
    doc_serialized = _serialize(doc)
    doc_serialized["live_endpoint_count"] = endpoint_count
    return doc_serialized


@router.post("", status_code=201)
async def create_range(body: dict[str, Any], user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Create a monitored range."""
    db = get_database()
    collection = db["ranges"]

    now = datetime.now(timezone.utc).isoformat()
    body["created_by"] = user["user_id"]
    body.setdefault("created_at", now)
    body.setdefault("updated_at", now)
    body.setdefault("monitoring", {
        "enabled": False,
        "interval_hours": 24,
    })
    body.setdefault("stats", {
        "total_endpoints": 0,
        "by_protocol": {},
        "by_risk": {},
        "no_auth_count": 0,
    })
    body.setdefault("scan_ids", [])
    body.setdefault("tags", [])

    if "_id" not in body:
        import uuid
        body["_id"] = f"range_{uuid.uuid4().hex[:12]}"

    await collection.insert_one(body)
    return _serialize(body)


@router.put("/{range_id}")
async def update_range(range_id: str, body: dict[str, Any]) -> dict[str, Any]:
    """Update a range."""
    db = get_database()
    collection = db["ranges"]

    body["updated_at"] = datetime.now(timezone.utc).isoformat()
    body.pop("_id", None)
    body.pop("id", None)

    result = await collection.find_one_and_update(
        {"_id": range_id},
        {"$set": body},
        return_document=True,
    )
    if not result:
        raise HTTPException(status_code=404, detail="Range not found")
    return _serialize(result)


@router.delete("/{range_id}", status_code=204)
async def delete_range(range_id: str, user: dict = Depends(get_current_user)) -> None:
    """Delete a range."""
    db = get_database()
    collection = db["ranges"]
    result = await collection.delete_one({"_id": range_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Range not found")


@router.post("/{range_id}/scan", response_model=TriggerScanResponse)
async def trigger_scan(
    range_id: str,
    body: dict[str, Any] | None = None,
    user: dict = Depends(get_current_user),
) -> TriggerScanResponse:
    """Trigger a scan for this range.

    By default creates an **active** scan (httpx + Nuclei).
    Pass ``{"type": "ingestion"}`` in the body to create a 3P ingestion scan
    that runs all predefined Shodan queries scoped to the range's CIDR.
    """
    db = get_database()
    ranges_collection = db["ranges"]
    scans_collection = db["scans"]

    # Verify range exists
    range_doc = await ranges_collection.find_one({"_id": range_id})
    if not range_doc:
        raise HTTPException(status_code=404, detail="Range not found")

    body = body or {}
    scan_type = body.get("type", "active")
    cidr = range_doc.get("cidr", "")

    import uuid
    now = datetime.now(timezone.utc).isoformat()
    scan_id = f"scan_{uuid.uuid4().hex[:12]}"

    if scan_type == "ingestion":
        scan_doc = {
            "_id": scan_id,
            "name": f"Shodan Ingestion for {range_doc.get('name', range_id)}",
            "type": "ingestion",
            "status": "queued",
            "config": {
                "type": "ingestion",
                "source": "shodan",
                "target": cidr,
                "range_id": range_id,
                "max_results_per_query": body.get("max_results_per_query", 100),
                # queries=None means run ALL predefined queries
            },
            "progress": {
                "total_hosts": 0,
                "scanned": 0,
                "alive": 0,
                "agents_found": 0,
                "percent_complete": 0.0,
            },
            "results_summary": {
                "total_endpoints": 0,
                "by_protocol": {},
                "by_risk": {},
                "no_auth_count": 0,
            },
            "endpoint_ids": [],
            "created_by": range_doc.get("created_by"),
            "created_at": now,
            "updated_at": now,
        }
    else:
        scan_doc = {
            "_id": scan_id,
            "name": f"Scan for {range_doc.get('name', range_id)}",
            "type": "active",
            "status": "queued",
            "config": {
                "target": cidr,
                "range_id": range_id,
            },
            "progress": {
                "total_hosts": range_doc.get("total_hosts", 0),
                "scanned": 0,
                "alive": 0,
                "agents_found": 0,
                "percent_complete": 0.0,
            },
            "results_summary": {
                "total_endpoints": 0,
                "by_protocol": {},
                "by_risk": {},
                "no_auth_count": 0,
            },
            "endpoint_ids": [],
            "created_by": range_doc.get("created_by"),
            "created_at": now,
            "updated_at": now,
        }

    await scans_collection.insert_one(scan_doc)

    # Update range with new scan reference
    await ranges_collection.update_one(
        {"_id": range_id},
        {
            "$push": {"scan_ids": scan_id},
            "$set": {
                "monitoring.last_scan_id": scan_id,
                "monitoring.last_scanned_at": now,
                "updated_at": now,
            },
        },
    )

    return TriggerScanResponse(scan_id=scan_id, range_id=range_id, status="queued")
