"""Enrichment pipeline for AIMap endpoints.

Takes raw endpoint documents from MongoDB and enriches them with:
- Framework detection from Shodan HTTP headers
- Tool extraction from Nuclei findings
- Live probing of well-known API endpoints (Ollama, OpenAI-compat, Gradio, ComfyUI, etc.)
- Risk scoring based on auth status, tool risk, and dangerous combos
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.discovery.nuclei_runner import NucleiRunner
from app.services.live_probe import probe_endpoint

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def enrich_endpoint(db: Any, endpoint_id: str) -> dict:
    """Enrich a single endpoint by its ``_id``.

    Fetches the document from MongoDB, runs Shodan and Nuclei enrichment,
    computes a risk score, writes the updates back, and returns the updated doc.

    Parameters
    ----------
    db:
        An ``AsyncIOMotorDatabase`` instance.
    endpoint_id:
        The ``_id`` of the endpoint document.

    Returns
    -------
    dict
        The updated endpoint document.

    Raises
    ------
    ValueError
        If the endpoint is not found.
    """
    collection = db["endpoints"]
    doc = await collection.find_one({"_id": endpoint_id})
    if not doc:
        raise ValueError(f"Endpoint not found: {endpoint_id}")

    updates: dict[str, Any] = {}

    # Enrich from Shodan sources
    shodan_enrichment = enrich_from_shodan_sources(doc)
    if shodan_enrichment:
        updates.update(shodan_enrichment)

    # Enrich from Nuclei sources
    nuclei_enrichment = enrich_from_nuclei_sources(doc)
    if nuclei_enrichment:
        updates.update(nuclei_enrichment)

    # Live probe: hit well-known API endpoints (Ollama, OpenAI-compat, etc.)
    try:
        merged_for_probe = {**doc, **updates}
        live_enrichment = await probe_endpoint(merged_for_probe)
        if live_enrichment:
            updates.update(live_enrichment)
    except Exception:
        logger.debug("Live probe failed for %s", endpoint_id, exc_info=True)

    # Merge updates into the doc for risk scoring
    merged = {**doc, **updates}

    # Compute risk score
    risk_score, risk_factors = compute_risk_score(merged)
    updates["risk_score"] = risk_score
    updates["risk_factors"] = risk_factors

    # Detect dangerous combos
    dangerous_combos = _detect_dangerous_combos(merged)
    if dangerous_combos:
        existing_combos = set(doc.get("dangerous_combos", []))
        updates["dangerous_combos"] = list(existing_combos | set(dangerous_combos))

    updates["updated_at"] = datetime.now(timezone.utc).isoformat()

    await collection.update_one({"_id": endpoint_id}, {"$set": updates})

    # Return the merged document
    updated_doc = await collection.find_one({"_id": endpoint_id})
    return updated_doc


def enrich_from_shodan_sources(doc: dict) -> dict:
    """Extract framework / auth info from Shodan raw_data in the sources array.

    Parses HTTP headers to detect frameworks (uvicorn -> fastapi, aiohttp,
    express, gunicorn -> python) and detects auth status from HTTP status codes
    or WWW-Authenticate headers.

    Parameters
    ----------
    doc:
        The full endpoint document from MongoDB.

    Returns
    -------
    dict
        A dict of enriched fields to ``$set`` on the document.
    """
    updates: dict[str, Any] = {}
    sources = doc.get("sources", [])

    for src in sources:
        if src.get("source") != "shodan":
            continue

        raw = src.get("raw_data", {})
        if not raw:
            continue

        # ── Framework detection from HTTP headers ──────────────
        http_data = raw.get("http", raw.get("data", ""))

        # If http_data is a dict (structured Shodan response)
        if isinstance(http_data, dict):
            server_header = http_data.get("server", "")
            html = http_data.get("html", "")
            status = http_data.get("status", 0)
            headers = http_data.get("headers", {})
        else:
            # http_data is a string (raw banner)
            server_header = ""
            html = ""
            status = 0
            headers = {}

            if isinstance(http_data, str):
                # Parse Server header from banner
                for line in http_data.split("\n"):
                    stripped = line.strip()
                    if stripped.lower().startswith("server:"):
                        server_header = stripped.split(":", 1)[1].strip()
                    elif stripped.startswith("HTTP/"):
                        try:
                            status = int(stripped.split(" ", 2)[1])
                        except (ValueError, IndexError):
                            pass
                    elif stripped.lower().startswith("www-authenticate:"):
                        headers["www-authenticate"] = stripped.split(":", 1)[1].strip()

        # Also check top-level raw_data fields
        if not server_header:
            server_header = raw.get("http", {}).get("server", "") if isinstance(raw.get("http"), dict) else ""

        # Detect framework from server header
        framework = _detect_framework(server_header)
        if framework and not doc.get("framework"):
            updates["framework"] = framework

        # Set server info
        if server_header and not doc.get("server", {}).get("banner"):
            updates["server"] = {
                "banner": server_header,
                "headers": headers if isinstance(headers, dict) else {},
                "tls": raw.get("ssl", False) or raw.get("transport", "") == "tcp",
                "cors_open": _check_cors(headers),
            }

        # ── Auth detection ─────────────────────────────────────
        if doc.get("auth_status", "unknown") == "unknown":
            auth = _detect_auth_from_http(status, headers, server_header)
            if auth != "unknown":
                updates["auth_status"] = auth

        # ── Parse HTML/data for MCP JSON responses ─────────────
        body_text = html if html else ""
        if not body_text and isinstance(raw.get("data"), str):
            # Try to find JSON in the raw data banner
            body_text = raw["data"]

        if body_text:
            _extract_mcp_from_body(body_text, doc, updates)

    return updates


def enrich_from_nuclei_sources(doc: dict) -> dict:
    """Extract tools / capabilities from Nuclei sources using grouped normalization.

    Finds all Nuclei source entries in the document's ``sources`` array, collects
    their ``raw_data`` findings, and runs them through
    ``NucleiRunner.normalize_findings_group()`` to extract tools, framework, etc.

    Parameters
    ----------
    doc:
        The full endpoint document from MongoDB.

    Returns
    -------
    dict
        A dict of enriched fields to ``$set`` on the document.
    """
    updates: dict[str, Any] = {}
    sources = doc.get("sources", [])

    nuclei_findings: list[dict] = []
    for src in sources:
        if src.get("source") != "nuclei":
            continue
        raw = src.get("raw_data", {})
        if raw:
            nuclei_findings.append(raw)

    if not nuclei_findings:
        return updates

    # Use the new grouped normalization
    enriched = NucleiRunner.normalize_findings_group(nuclei_findings)
    if not enriched:
        return updates

    # Only update fields that add value
    if enriched.get("framework") and not doc.get("framework"):
        updates["framework"] = enriched["framework"]

    if enriched.get("auth_status") != "unknown" and doc.get("auth_status", "unknown") == "unknown":
        updates["auth_status"] = enriched["auth_status"]

    if enriched.get("tools") and (not doc.get("tools") or len(enriched["tools"]) > len(doc.get("tools", []))):
        updates["tools"] = enriched["tools"]
        updates["tool_count"] = enriched.get("tool_count", len(enriched["tools"]))

    if enriched.get("system_prompt") and not doc.get("system_prompt"):
        updates["system_prompt"] = enriched["system_prompt"]
        updates["system_prompt_extracted"] = True

    if enriched.get("server", {}).get("banner") and not doc.get("server", {}).get("banner"):
        updates["server"] = enriched["server"]

    return updates


def compute_risk_score(doc: dict) -> tuple[float, list[str]]:
    """Compute a risk score (0.0 -- 10.0) for an endpoint.

    Scoring factors:
    - auth_status == "none" -> +4.0
    - auth_status == "unknown" -> +1.0
    - tool_count >= 10 -> +2.0; >= 5 -> +1.0
    - Each critical-risk tool -> +1.0; each high-risk tool -> +0.5
    - cors_open -> +1.0
    - No TLS -> +0.5
    - system_prompt_extracted -> +0.5
    - Dangerous combos -> +1.0 each

    Parameters
    ----------
    doc:
        The endpoint document (possibly already partially enriched).

    Returns
    -------
    tuple[float, list[str]]
        (clamped risk score, list of risk factor labels)
    """
    score = 0.0
    factors: list[str] = []

    # Auth status
    auth = doc.get("auth_status", "unknown")
    if auth == "none":
        score += 4.0
        factors.append("no_auth")
    elif auth == "unknown":
        score += 1.0
        factors.append("auth_unknown")

    # Tool count
    tool_count = doc.get("tool_count", 0)
    if tool_count >= 10:
        score += 2.0
        factors.append("many_tools")
    elif tool_count >= 5:
        score += 1.0
        factors.append("many_tools")

    # Individual tool risk
    tools = doc.get("tools", [])
    for tool in tools:
        risk = tool.get("risk", "info")
        if risk == "critical":
            score += 1.0
            factors.append(f"critical_tool:{tool.get('name', '?')}")
        elif risk == "high":
            score += 0.5
            factors.append(f"high_tool:{tool.get('name', '?')}")

    # CORS
    server = doc.get("server", {})
    if server.get("cors_open"):
        score += 1.0
        factors.append("cors_open")

    # TLS
    if not server.get("tls"):
        score += 0.5
        factors.append("no_tls")

    # System prompt leaked
    if doc.get("system_prompt_extracted"):
        score += 0.5
        factors.append("system_prompt_leaked")

    # Models exposed (from live probe)
    tags = doc.get("tags", [])
    risk_factors_existing = doc.get("risk_factors", [])

    if "models_exposed" in risk_factors_existing:
        score += 1.0
        factors.append("models_exposed")

    if "uncensored_model" in risk_factors_existing:
        score += 2.0
        factors.append("uncensored_model")

    if "signup_enabled" in risk_factors_existing:
        score += 1.5
        factors.append("signup_enabled")

    if "actively_serving" in tags and auth == "none":
        score += 0.5
        factors.append("actively_serving_no_auth")

    # Dangerous combos
    combos = _detect_dangerous_combos(doc)
    for combo in combos:
        score += 1.0
        factors.append(f"dangerous_combo:{combo}")

    # Clamp
    score = max(0.0, min(10.0, score))

    return score, factors


async def enrich_all(db: Any, batch_size: int = 50) -> dict:
    """Batch-enrich all endpoints (or those with risk_score == 0).

    Parameters
    ----------
    db:
        An ``AsyncIOMotorDatabase`` instance.
    batch_size:
        Number of endpoints to process per batch.

    Returns
    -------
    dict
        Stats: total processed, enriched count, errors count.
    """
    collection = db["endpoints"]

    # Find endpoints that haven't been enriched yet (risk_score == 0)
    query = {"$or": [{"risk_score": 0}, {"risk_score": 0.0}, {"risk_score": {"$exists": False}}]}
    total = await collection.count_documents(query)

    logger.info("Enriching %d endpoints in batches of %d", total, batch_size)

    processed = 0
    enriched = 0
    errors = 0
    skip = 0

    while skip < total:
        cursor = collection.find(query).skip(skip).limit(batch_size)
        batch_ids: list[str] = []
        async for doc in cursor:
            batch_ids.append(doc["_id"])

        if not batch_ids:
            break

        for doc_id in batch_ids:
            try:
                await enrich_endpoint(db, doc_id)
                enriched += 1
            except Exception:
                logger.exception("Failed to enrich endpoint %s", doc_id)
                errors += 1
            processed += 1

        # Since we update docs matching the query, re-query from 0
        # (processed docs no longer match risk_score==0)
        skip = 0
        remaining = await collection.count_documents(query)
        if remaining == 0:
            break

    stats = {
        "total": total,
        "processed": processed,
        "enriched": enriched,
        "errors": errors,
    }
    logger.info("Enrichment complete: %s", stats)
    return stats


async def ingest_nuclei_findings(db: Any, findings_file: str) -> dict:
    """Ingest Nuclei JSONL findings file: parse, group, upsert, enrich.

    Parameters
    ----------
    db:
        An ``AsyncIOMotorDatabase`` instance.
    findings_file:
        Path to a Nuclei JSONL output file.

    Returns
    -------
    dict
        Stats: total findings, groups, upserted, enriched, errors.

    Raises
    ------
    FileNotFoundError
        If the findings file does not exist.
    """
    fpath = Path(findings_file)
    if not fpath.is_file():
        raise FileNotFoundError(f"Findings file not found: {findings_file}")

    # Parse JSONL
    all_findings: list[dict] = NucleiRunner._parse_jsonl(findings_file)
    if not all_findings:
        return {"total_findings": 0, "groups": 0, "upserted": 0, "enriched": 0, "errors": 0}

    # Group by (ip, port)
    groups = NucleiRunner.group_findings_by_target(all_findings)
    logger.info("Parsed %d findings into %d target groups", len(all_findings), len(groups))

    collection = db["endpoints"]
    upserted_ids: list[str] = []
    errors = 0

    for (ip, port), group_findings in groups.items():
        try:
            # Normalize the group into a single endpoint dict
            normalized = NucleiRunner.normalize_findings_group(group_findings)
            if not normalized or not normalized.get("ip"):
                continue

            # Upsert to MongoDB
            doc_id = await _upsert_endpoint(collection, normalized)
            upserted_ids.append(doc_id)
        except Exception:
            logger.exception("Failed to upsert findings for %s:%s", ip, port)
            errors += 1

    # Run enrichment on upserted endpoints
    enriched = 0
    for doc_id in upserted_ids:
        try:
            await enrich_endpoint(db, doc_id)
            enriched += 1
        except Exception:
            logger.exception("Failed to enrich endpoint %s after ingest", doc_id)
            errors += 1

    stats = {
        "total_findings": len(all_findings),
        "groups": len(groups),
        "upserted": len(upserted_ids),
        "enriched": enriched,
        "errors": errors,
    }
    logger.info("Nuclei ingest complete: %s", stats)
    return stats


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _detect_framework(server_header: str) -> str:
    """Detect web framework from an HTTP Server header value."""
    if not server_header:
        return ""

    lower = server_header.lower()

    if "uvicorn" in lower:
        return "fastapi"
    if "aiohttp" in lower:
        return "aiohttp"
    if "express" in lower:
        return "express"
    if "gunicorn" in lower:
        return "python"
    if "werkzeug" in lower:
        return "flask"
    if "next" in lower:
        return "nextjs"
    if "nginx" in lower:
        return "nginx"

    return ""


def _check_cors(headers: dict) -> bool:
    """Check if CORS is fully open (Access-Control-Allow-Origin: *)."""
    if not headers:
        return False

    # Headers may be dict or case-insensitive
    for key, value in headers.items():
        if key.lower() == "access-control-allow-origin" and value.strip() == "*":
            return True
    return False


def _detect_auth_from_http(status: int, headers: dict, server_header: str) -> str:
    """Detect auth status from HTTP status code and headers."""
    if status in (401, 403):
        # Check for WWW-Authenticate header
        if isinstance(headers, dict):
            for key, value in headers.items():
                if key.lower() == "www-authenticate":
                    val_lower = value.lower()
                    if "bearer" in val_lower:
                        return "oauth"
                    if "basic" in val_lower:
                        return "basic"
                    return "api_key"
        return "api_key"
    elif status == 200:
        return "none"

    return "unknown"


def _extract_mcp_from_body(body_text: str, doc: dict, updates: dict) -> None:
    """Try to extract MCP initialize response data from an HTTP body."""
    # Look for JSON in body
    try:
        # Find the first JSON object in the text
        start = body_text.find("{")
        if start == -1:
            return

        # Try to parse from the first '{' to end
        candidate = body_text[start:]
        body_json = json.loads(candidate)

        if not isinstance(body_json, dict):
            return

        # MCP initialize response
        result = body_json.get("result", {})
        if isinstance(result, dict):
            server_info = result.get("serverInfo", {})
            if server_info and not doc.get("framework"):
                name = server_info.get("name", "")
                version = server_info.get("version", "")
                if name:
                    updates.setdefault("framework", name)

            instructions = result.get("instructions", "")
            if instructions and not doc.get("system_prompt"):
                updates["system_prompt"] = instructions
                updates["system_prompt_extracted"] = True

    except (json.JSONDecodeError, ValueError):
        pass


def _detect_dangerous_combos(doc: dict) -> list[str]:
    """Detect dangerous tool combinations in an endpoint.

    Patterns:
    - exec/shell + no auth -> "exec_no_auth"
    - database read + write tools -> "db_read_write"
    - file read + file write -> "file_read_write"
    - admin tools + no auth -> "admin_no_auth"
    """
    combos: list[str] = []
    tools = doc.get("tools", [])
    auth = doc.get("auth_status", "unknown")

    if not tools:
        return combos

    tool_names_lower = [t.get("name", "").lower() for t in tools]
    tool_risks = {t.get("name", "").lower(): t.get("risk", "info") for t in tools}
    combined_text = " ".join(tool_names_lower)

    has_exec = any(
        p in combined_text
        for p in ["exec", "shell", "run_command", "eval", "execute"]
    )
    has_admin = any(
        p in combined_text
        for p in ["admin", "deploy", "config", "manage"]
    )
    has_db_read = any(
        p in combined_text
        for p in ["query", "select", "read_db", "get_record", "db_read"]
    )
    has_db_write = any(
        p in combined_text
        for p in ["insert", "update_db", "delete_record", "db_write", "sql_write"]
    )
    has_file_read = any(
        p in combined_text
        for p in ["read_file", "get_file", "file_read", "download"]
    )
    has_file_write = any(
        p in combined_text
        for p in ["write_file", "put_file", "file_write", "upload"]
    )

    if has_exec and auth == "none":
        combos.append("exec_no_auth")

    if has_admin and auth == "none":
        combos.append("admin_no_auth")

    if has_db_read and has_db_write:
        combos.append("db_read_write")

    if has_file_read and has_file_write:
        combos.append("file_read_write")

    return combos


async def _upsert_endpoint(collection: Any, normalized: dict) -> str:
    """Insert or merge a normalized endpoint dict into MongoDB.

    Mirrors the logic in ``SourceAdapter._upsert()`` but works standalone.

    Returns the ``_id`` of the upserted document.
    """
    import uuid

    ip = normalized["ip"]
    port = normalized["port"]
    now = datetime.now(timezone.utc)

    existing = await collection.find_one({"ip": ip, "port": port})

    if existing is not None:
        doc_id: str = existing["_id"]
        update_set: dict[str, Any] = {
            "last_seen": now.isoformat(),
            "updated_at": now.isoformat(),
        }

        # Update top-level fields only when incoming data is richer
        merge_fields = [
            "hostname", "url", "framework", "model", "protocol",
        ]
        for field in merge_fields:
            incoming = normalized.get(field)
            current = existing.get(field)
            if incoming and not current:
                update_set[field] = incoming

        # Auth: update if incoming is not "unknown" and current IS "unknown"
        if normalized.get("auth_status", "unknown") != "unknown" and existing.get("auth_status", "unknown") == "unknown":
            update_set["auth_status"] = normalized["auth_status"]

        # Tools: update if incoming has more
        incoming_tools = normalized.get("tools", [])
        current_tools = existing.get("tools", [])
        if incoming_tools and (not current_tools or len(incoming_tools) > len(current_tools)):
            update_set["tools"] = incoming_tools
            update_set["tool_count"] = normalized.get("tool_count", len(incoming_tools))

        # System prompt
        if normalized.get("system_prompt") and not existing.get("system_prompt"):
            update_set["system_prompt"] = normalized["system_prompt"]
            update_set["system_prompt_extracted"] = True

        # Server info
        incoming_server = normalized.get("server", {})
        current_server = existing.get("server", {})
        if incoming_server.get("banner") and not current_server.get("banner"):
            update_set["server"] = incoming_server

        # Merge sources: append new nuclei sources
        incoming_sources = normalized.get("sources", [])
        current_sources: list[dict] = list(existing.get("sources", []))
        for src in incoming_sources:
            current_sources.append(src)
        update_set["sources"] = current_sources

        # Geo
        incoming_geo = normalized.get("geo", {})
        current_geo = existing.get("geo", {})
        if incoming_geo and not current_geo.get("country"):
            update_set["geo"] = incoming_geo

        await collection.update_one({"_id": doc_id}, {"$set": update_set})
        logger.debug("Merged endpoint %s for %s:%s", doc_id, ip, port)
        return doc_id

    # Insert new
    doc_id = f"ep_{uuid.uuid4().hex[:12]}"
    doc = {
        "_id": doc_id,
        "ip": ip,
        "port": port,
        "hostname": normalized.get("hostname", ""),
        "url": normalized.get("url", ""),
        "protocol": normalized.get("protocol", "mcp"),
        "framework": normalized.get("framework", ""),
        "model": normalized.get("model", ""),
        "auth_status": normalized.get("auth_status", "unknown"),
        "tools": normalized.get("tools", []),
        "tool_count": normalized.get("tool_count", 0),
        "dangerous_combos": normalized.get("dangerous_combos", []),
        "system_prompt": normalized.get("system_prompt", ""),
        "system_prompt_extracted": normalized.get("system_prompt_extracted", False),
        "risk_score": normalized.get("risk_score", 0.0),
        "risk_factors": normalized.get("risk_factors", []),
        "geo": normalized.get("geo", {}),
        "server": normalized.get("server", {}),
        "sources": normalized.get("sources", []),
        "range_id": normalized.get("range_id"),
        "scan_ids": normalized.get("scan_ids", []),
        "analysis_id": normalized.get("analysis_id"),
        "first_seen": now.isoformat(),
        "last_seen": now.isoformat(),
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
        "tags": normalized.get("tags", []),
    }

    await collection.insert_one(doc)
    logger.debug("Inserted new endpoint %s for %s:%s", doc_id, ip, port)
    return doc_id
