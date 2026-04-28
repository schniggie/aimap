"""Agent Endpoints CRUD + Search routes."""

import os
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from app.database import get_database
from app.services.search import parse_search_query

# Safe base directory for nuclei findings ingestion
_INGEST_BASE_DIR = os.environ.get("INGEST_BASE_DIR", "/tmp/")

router = APIRouter(prefix="/endpoints", tags=["endpoints"])


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class PaginatedResponse(BaseModel):
    items: list[dict[str, Any]]
    total: int
    page: int
    page_size: int


class StatsResponse(BaseModel):
    total: int
    by_protocol: dict[str, int]
    by_risk: dict[str, int]
    by_auth: dict[str, int]
    no_auth_count: int


class GeoEntry(BaseModel):
    country: str
    country_code: str
    lat: float
    lon: float
    count: int


class SearchRequest(BaseModel):
    query: str


class IngestNucleiRequest(BaseModel):
    findings_file: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _serialize(doc: dict) -> dict:
    """Convert MongoDB doc _id to string id (returns a shallow copy)."""
    if not doc:
        return doc
    out = {k: v for k, v in doc.items() if k != "_id"}
    if "_id" in doc:
        out["id"] = str(doc["_id"])
    return out


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("", response_model=PaginatedResponse)
async def list_endpoints(
    protocol: str | None = None,
    auth_status: str | None = None,
    risk_min: float | None = None,
    risk_max: float | None = None,
    country: str | None = None,
    tool: str | None = None,
    tag: str | None = None,
    q: str | None = None,
    sort_by: str = "risk_score",
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
) -> PaginatedResponse:
    """List/search endpoints with filters and pagination."""
    db = get_database()
    collection = db["endpoints"]

    query: dict[str, Any] = {}
    if protocol:
        query["protocol"] = protocol
    if auth_status:
        query["auth_status"] = auth_status
    if risk_min is not None or risk_max is not None:
        risk_filter: dict[str, float] = {}
        if risk_min is not None:
            risk_filter["$gte"] = risk_min
        if risk_max is not None:
            risk_filter["$lte"] = risk_max
        query["risk_score"] = risk_filter
    if country:
        query["geo.country_code"] = country.upper()
    if tool:
        query["tools.name"] = tool
    if tag:
        query["tags"] = tag
    if q:
        query["$text"] = {"$search": q}

    # Determine sort direction
    sort_field = sort_by
    sort_dir = -1  # descending by default
    if sort_by.startswith("-"):
        sort_field = sort_by[1:]
        sort_dir = -1
    elif sort_by.startswith("+"):
        sort_field = sort_by[1:]
        sort_dir = 1

    skip = (page - 1) * page_size
    total = await collection.count_documents(query)
    cursor = collection.find(query).sort(sort_field, sort_dir).skip(skip).limit(page_size)
    items = [_serialize(doc) async for doc in cursor]

    return PaginatedResponse(items=items, total=total, page=page, page_size=page_size)


@router.get("/stats", response_model=StatsResponse)
async def get_stats() -> StatsResponse:
    """Aggregation stats for the dashboard."""
    db = get_database()
    collection = db["endpoints"]

    total = await collection.count_documents({})

    # by_protocol
    proto_cursor = collection.aggregate([
        {"$group": {"_id": "$protocol", "count": {"$sum": 1}}}
    ])
    by_protocol = {doc["_id"]: doc["count"] async for doc in proto_cursor}

    # by_risk (bucket by score)
    risk_buckets = {
        "critical": {"$gte": 9.0},
        "high": {"$gte": 7.0, "$lt": 9.0},
        "medium": {"$gte": 4.0, "$lt": 7.0},
        "low": {"$gte": 1.0, "$lt": 4.0},
        "info": {"$lt": 1.0},
    }
    by_risk: dict[str, int] = {}
    for level, condition in risk_buckets.items():
        by_risk[level] = await collection.count_documents({"risk_score": condition})

    # by_auth
    auth_cursor = collection.aggregate([
        {"$group": {"_id": "$auth_status", "count": {"$sum": 1}}}
    ])
    by_auth = {doc["_id"]: doc["count"] async for doc in auth_cursor}

    no_auth_count = await collection.count_documents({"auth_status": "none"})

    return StatsResponse(
        total=total,
        by_protocol=by_protocol,
        by_risk=by_risk,
        by_auth=by_auth,
        no_auth_count=no_auth_count,
    )


@router.get("/geo", response_model=list[GeoEntry])
async def get_geo() -> list[GeoEntry]:
    """Geo aggregation for the map view."""
    db = get_database()
    collection = db["endpoints"]

    pipeline = [
        {"$match": {"geo.country_code": {"$exists": True}}},
        {
            "$group": {
                "_id": "$geo.country_code",
                "country": {"$first": "$geo.country"},
                "lat": {"$avg": "$geo.lat"},
                "lon": {"$avg": "$geo.lon"},
                "count": {"$sum": 1},
            }
        },
        {"$sort": {"count": -1}},
    ]
    cursor = collection.aggregate(pipeline)
    results: list[GeoEntry] = []
    async for doc in cursor:
        results.append(
            GeoEntry(
                country=doc.get("country", doc["_id"]),
                country_code=doc["_id"],
                lat=doc.get("lat", 0.0),
                lon=doc.get("lon", 0.0),
                count=doc["count"],
            )
        )
    return results


@router.get("/globe")
async def get_globe_data() -> list[dict[str, Any]]:
    """Per-endpoint geo data optimized for the 3D globe visualization.

    Returns lightweight records with lat/lng, risk, protocol for each
    endpoint that has valid geo coordinates.
    """
    db = get_database()
    collection = db["endpoints"]

    cursor = collection.find(
        {"geo.lat": {"$exists": True}},
        {
            "_id": 1,
            "ip": 1,
            "port": 1,
            "protocol": 1,
            "risk_score": 1,
            "auth_status": 1,
            "tool_count": 1,
            "geo.lat": 1,
            "geo.lon": 1,
            "geo.country_code": 1,
            "geo.city": 1,
            "hostname": 1,
            "model": 1,
        },
    )

    results: list[dict[str, Any]] = []
    async for doc in cursor:
        geo = doc.get("geo", {})
        lat = geo.get("lat", 0)
        lon = geo.get("lon", 0)
        # Skip entries with no real coordinates
        if lat == 0 and lon == 0:
            continue
        results.append({
            "id": str(doc["_id"]),
            "ip": doc.get("ip", ""),
            "port": doc.get("port", 0),
            "protocol": doc.get("protocol", "unknown"),
            "risk_score": doc.get("risk_score", 0),
            "auth_status": doc.get("auth_status", "unknown"),
            "tool_count": doc.get("tool_count", 0),
            "lat": lat,
            "lng": lon,
            "country_code": geo.get("country_code", ""),
            "city": geo.get("city", ""),
            "hostname": doc.get("hostname", ""),
            "model": doc.get("model", ""),
        })

    return results


@router.post("/enrich-all")
async def enrich_all_endpoints() -> dict[str, Any]:
    """Batch-enrich all endpoints that haven't been enriched yet."""
    from app.services.enrichment import enrich_all

    db = get_database()
    stats = await enrich_all(db)
    return stats


@router.post("/ingest-nuclei")
async def ingest_nuclei(body: IngestNucleiRequest) -> dict[str, Any]:
    """Ingest a Nuclei JSONL findings file into the database."""
    from app.services.enrichment import ingest_nuclei_findings

    # Validate that the file path is within the allowed base directory
    if ".." in body.findings_file:
        raise HTTPException(status_code=400, detail="Path must not contain '..'")
    resolved = os.path.realpath(body.findings_file)
    if not resolved.startswith(os.path.realpath(_INGEST_BASE_DIR)):
        raise HTTPException(
            status_code=400,
            detail=f"Path must be within {_INGEST_BASE_DIR}",
        )

    db = get_database()
    try:
        stats = await ingest_nuclei_findings(db, resolved)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return stats


@router.post("/{endpoint_id}/enrich")
async def enrich_single_endpoint(endpoint_id: str) -> dict[str, Any]:
    """Enrich a single endpoint by ID."""
    from app.services.enrichment import enrich_endpoint

    db = get_database()
    try:
        updated = await enrich_endpoint(db, endpoint_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return _serialize(updated)


@router.get("/{endpoint_id}")
async def get_endpoint(endpoint_id: str) -> dict[str, Any]:
    """Get a single endpoint by ID."""
    db = get_database()
    collection = db["endpoints"]
    doc = await collection.find_one({"_id": endpoint_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return _serialize(doc)


@router.post("", status_code=201)
async def create_endpoint(body: dict[str, Any]) -> dict[str, Any]:
    """Create a new endpoint (used by discovery engine)."""
    db = get_database()
    collection = db["endpoints"]

    now = datetime.now(timezone.utc).isoformat()
    body.setdefault("created_at", now)
    body.setdefault("updated_at", now)
    body.setdefault("first_seen", now)
    body.setdefault("last_seen", now)

    # Generate an ID if not provided
    if "_id" not in body:
        import uuid
        body["_id"] = f"ep_{uuid.uuid4().hex[:12]}"

    try:
        await collection.insert_one(body)
    except Exception as e:
        if "duplicate" in str(e).lower() or "E11000" in str(e):
            raise HTTPException(status_code=409, detail="Endpoint already exists")
        raise

    return _serialize(body)


@router.put("/{endpoint_id}")
async def update_endpoint(endpoint_id: str, body: dict[str, Any]) -> dict[str, Any]:
    """Update an endpoint."""
    db = get_database()
    collection = db["endpoints"]

    body["updated_at"] = datetime.now(timezone.utc).isoformat()
    # Don't allow changing _id
    body.pop("_id", None)
    body.pop("id", None)

    result = await collection.find_one_and_update(
        {"_id": endpoint_id},
        {"$set": body},
        return_document=True,
    )
    if not result:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return _serialize(result)


@router.delete("/{endpoint_id}", status_code=204)
async def delete_endpoint(endpoint_id: str) -> None:
    """Delete an endpoint."""
    db = get_database()
    collection = db["endpoints"]
    result = await collection.delete_one({"_id": endpoint_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Endpoint not found")


@router.post("/search")
async def advanced_search(
    body: SearchRequest,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
) -> PaginatedResponse:
    """Advanced search with Shodan-style query parsing."""
    db = get_database()
    collection = db["endpoints"]

    query = parse_search_query(body.query)
    skip = (page - 1) * page_size
    total = await collection.count_documents(query)
    cursor = collection.find(query).sort("risk_score", -1).skip(skip).limit(page_size)
    items = [_serialize(doc) async for doc in cursor]

    return PaginatedResponse(items=items, total=total, page=page, page_size=page_size)
