"""Attack / Security Testing routes.

Provides endpoints to launch attack tests against discovered endpoints
and stream results in real-time via WebSocket.
Dispatches to protocol-specific attack engines (MCP, Ollama, etc.).

Log streaming uses Redis Streams when available, falling back to
in-memory buffers for local development without Redis.
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field
from starlette.requests import Request

from app.auth import get_current_user
from app.config import settings
from app.database import get_database
from app.limiter import limiter
from app.services.attack_mcp import MCPAttackEngine
from app.services.attack_ollama import OllamaAttackEngine
from app.services.attack_openclaw import OpenClawAttackEngine
from app.services.attack_openai import OpenAIAttackEngine
from app.services.concurrency import acquire_slot, release_slot
from app.services.redis_client import get_redis

router = APIRouter(prefix="/attack", tags=["attack"])
logger = logging.getLogger(__name__)

# Track active attack tasks (process-local, needed for cancellation)
_active_attacks: dict[str, asyncio.Task] = {}

# In-memory fallback when Redis is unavailable
_fallback_logs: dict[str, list[dict]] = {}
_fallback_done: dict[str, asyncio.Event] = {}

# Redis key helpers
_STREAM_KEY = "attack:{attack_id}:logs"
_STATUS_KEY = "attack:{attack_id}:status"
_STREAM_MAXLEN = 5000
_STATUS_TTL = 3600  # 1 hour


def _stream_key(attack_id: str) -> str:
    return f"attack:{attack_id}:logs"


def _status_key(attack_id: str) -> str:
    return f"attack:{attack_id}:status"


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class AttackRequest(BaseModel):
    techniques: list[str] = ["prompt_injection", "tool_injection", "data_exfil"]
    depth: str = "standard"
    max_steps: int = Field(default=20, ge=1, le=100)


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


async def _append_log(attack_id: str, entry: dict) -> None:
    """Append a log entry to Redis Stream or in-memory fallback."""
    r = await get_redis()
    if r is not None:
        await r.xadd(
            _stream_key(attack_id),
            {"data": json.dumps(entry)},
            maxlen=_STREAM_MAXLEN,
        )
    else:
        if attack_id in _fallback_logs:
            _fallback_logs[attack_id].append(entry)


async def _mark_done(attack_id: str) -> None:
    """Signal that an attack has completed."""
    r = await get_redis()
    if r is not None:
        await r.set(_status_key(attack_id), "completed", ex=_STATUS_TTL)
    else:
        event = _fallback_done.get(attack_id)
        if event:
            event.set()


async def _is_attack_known(attack_id: str) -> bool:
    """Check if an attack exists (either in Redis or fallback)."""
    r = await get_redis()
    if r is not None:
        # Check if the stream or status key exists
        return (
            await r.exists(_stream_key(attack_id))
            or await r.exists(_status_key(attack_id))
        )
    return attack_id in _fallback_logs


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/{endpoint_id}")
@limiter.limit("10/minute")
async def start_attack(request: Request, endpoint_id: str, body: AttackRequest, user: dict = Depends(get_current_user)) -> dict[str, Any]:
    """Launch an attack against an MCP endpoint.

    Returns an attack_id that can be used to stream results via WebSocket.
    """
    db = get_database()

    # Look up the endpoint to get its URL
    endpoint = await db["endpoints"].find_one({"_id": endpoint_id})
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    # Always build URL from ip:port to ensure it's valid
    ip = endpoint.get("ip", "")
    port = endpoint.get("port", 80)
    scheme = "https" if endpoint.get("server", {}).get("tls") else "http"
    target_url = f"{scheme}://{ip}:{port}"

    attack_id = f"atk_{uuid.uuid4().hex[:12]}"

    # Mark testing as running on the analysis doc
    now = datetime.now(timezone.utc).isoformat()
    await db["analyses"].update_one(
        {"endpoint_id": endpoint_id},
        {
            "$set": {
                "testing.status": "running",
                "testing.last_tested_at": now,
                "updated_at": now,
            }
        },
        upsert=True,
    )

    protocol = endpoint.get("protocol", "unknown")

    # Initialize Redis state before dispatch (so WebSocket can connect immediately)
    r = await get_redis()
    if r is not None:
        await r.set(_status_key(attack_id), "running", ex=_STATUS_TTL)
    else:
        _fallback_logs[attack_id] = []
        _fallback_done[attack_id] = asyncio.Event()

    # Try Modal serverless dispatch (requires Redis for cross-process log streaming)
    modal_dispatched = False
    if settings.MODAL_ENABLED and r is not None:
        try:
            import modal

            fn = modal.Function.from_name("aimap", "run_attack_task")
            fn.spawn(
                attack_id=attack_id,
                endpoint_id=endpoint_id,
                target_url=target_url,
                protocol=protocol,
                techniques=body.techniques,
                max_steps=body.max_steps,
                depth=body.depth,
            )
            modal_dispatched = True
            logger.info("Attack %s dispatched to Modal", attack_id)
        except Exception:
            logger.warning(
                "Modal dispatch failed for %s, falling back to local", attack_id
            )

    if not modal_dispatched:
        # Local execution with concurrency control
        slot = await acquire_slot("attack")
        if not slot:
            raise HTTPException(
                status_code=429,
                detail="Too many concurrent attacks. Please wait and try again.",
            )
        task = asyncio.create_task(
            _run_attack(attack_id, endpoint_id, target_url, protocol, body)
        )
        _active_attacks[attack_id] = task
        task.add_done_callback(lambda t: _active_attacks.pop(attack_id, None))

    return {
        "attack_id": attack_id,
        "endpoint_id": endpoint_id,
        "status": "running",
        "target_url": target_url,
        "protocol": protocol,
    }


@router.websocket("/{attack_id}/stream")
async def attack_stream(websocket: WebSocket, attack_id: str) -> None:
    """Stream live attack log entries over WebSocket.

    Uses Redis Streams (XREAD) when available, falling back to
    in-memory buffer polling for local dev.

    Auth: attack_id is a 48-bit random token issued by an authenticated POST,
    so possession implies authorization.
    """
    await websocket.accept()

    if not await _is_attack_known(attack_id):
        await websocket.send_json({"error": "Attack not found"})
        await websocket.close()
        return

    r = await get_redis()

    try:
        if r is not None:
            await _stream_from_redis(websocket, attack_id, r)
        else:
            await _stream_from_memory(websocket, attack_id)
    except WebSocketDisconnect:
        pass
    except Exception:
        logger.exception("WebSocket error for attack %s", attack_id)
    finally:
        if r is None:
            # In-memory cleanup after delay
            asyncio.get_event_loop().call_later(
                60,
                lambda: (
                    _fallback_logs.pop(attack_id, None),
                    _fallback_done.pop(attack_id, None),
                ),
            )


async def _stream_from_redis(
    websocket: WebSocket, attack_id: str, r: Any
) -> None:
    """Stream attack logs from a Redis Stream via XREAD."""
    last_id = "0-0"

    while True:
        # XREAD blocks for up to 300ms (replaces asyncio.sleep(0.3))
        entries = await r.xread(
            {_stream_key(attack_id): last_id},
            count=50,
            block=300,
        )

        if entries:
            # entries = [(stream_name, [(msg_id, fields), ...])]
            for _stream_name, messages in entries:
                for msg_id, fields in messages:
                    data = json.loads(fields["data"])
                    await websocket.send_json(data)
                    last_id = msg_id

                    if data.get("type") == "DONE":
                        return
        else:
            # No new messages — check if attack is done
            status = await r.get(_status_key(attack_id))
            if status == "completed":
                # Drain any remaining entries
                remaining = await r.xread(
                    {_stream_key(attack_id): last_id},
                    count=100,
                )
                if remaining:
                    for _sn, msgs in remaining:
                        for mid, fields in msgs:
                            data = json.loads(fields["data"])
                            await websocket.send_json(data)
                            if data.get("type") == "DONE":
                                return
                # If no DONE entry was found, send one
                await websocket.send_json(
                    {"type": "DONE", "content": "Attack complete"}
                )
                return


async def _stream_from_memory(
    websocket: WebSocket, attack_id: str
) -> None:
    """Stream attack logs from in-memory fallback (original behavior)."""
    cursor = 0
    while True:
        logs = _fallback_logs.get(attack_id, [])

        while cursor < len(logs):
            await websocket.send_json(logs[cursor])
            cursor += 1

        done_event = _fallback_done.get(attack_id)
        if done_event and done_event.is_set():
            logs = _fallback_logs.get(attack_id, [])
            while cursor < len(logs):
                await websocket.send_json(logs[cursor])
                cursor += 1
            await websocket.send_json(
                {"type": "DONE", "content": "Attack complete"}
            )
            break

        await asyncio.sleep(0.3)


@router.get("/{attack_id}/status")
async def get_attack_status(attack_id: str) -> dict[str, Any]:
    """Poll attack status and get buffered log entries."""
    r = await get_redis()

    if r is not None:
        status = await r.get(_status_key(attack_id))
        if status is None:
            raise HTTPException(status_code=404, detail="Attack not found")
        log_count = await r.xlen(_stream_key(attack_id))
        return {
            "attack_id": attack_id,
            "status": status,
            "log_count": log_count,
        }
    else:
        if attack_id not in _fallback_logs:
            raise HTTPException(status_code=404, detail="Attack not found")
        done_event = _fallback_done.get(attack_id)
        is_done = done_event.is_set() if done_event else False
        return {
            "attack_id": attack_id,
            "status": "completed" if is_done else "running",
            "log_count": len(_fallback_logs.get(attack_id, [])),
        }


# ---------------------------------------------------------------------------
# Background execution
# ---------------------------------------------------------------------------

async def _run_attack(
    attack_id: str,
    endpoint_id: str,
    target_url: str,
    protocol: str,
    config: AttackRequest,
) -> None:
    """Run the attack engine and stream log entries via Redis or fallback."""
    db = get_database()

    try:
        # Dispatch to protocol-specific attack engine
        engine_kwargs = dict(
            target_url=target_url,
            techniques=config.techniques,
            max_steps=config.max_steps,
            depth=config.depth,
        )
        if protocol == "ollama":
            engine = OllamaAttackEngine(**engine_kwargs)
        elif protocol == "openclaw":
            engine = OpenClawAttackEngine(**engine_kwargs)
        elif protocol in ("openai_compat", "gradio", "streamlit", "open_webui", "librechat"):
            engine = OpenAIAttackEngine(**engine_kwargs)
        else:
            # MCP, LangServe, AutoGen, and unknown — use MCP engine
            engine = MCPAttackEngine(**engine_kwargs)

        async for entry in engine.run():
            await _append_log(attack_id, entry)

        # Persist results to the analysis document
        testing_info = engine.build_testing_info()
        now = datetime.now(timezone.utc).isoformat()

        await db["analyses"].update_one(
            {"endpoint_id": endpoint_id},
            {
                "$set": {
                    "testing": testing_info,
                    "updated_at": now,
                },
                "$setOnInsert": {
                    "_id": f"an_{uuid.uuid4().hex[:12]}",
                    "endpoint_id": endpoint_id,
                    "created_at": now,
                },
            },
            upsert=True,
        )

        # Update endpoint risk score if critical findings
        critical_count = sum(
            1 for r in engine.results if r.success and r.severity == "critical"
        )
        high_count = sum(
            1 for r in engine.results if r.success and r.severity == "high"
        )
        if critical_count > 0 or high_count > 0:
            risk_bump = min(critical_count * 1.5 + high_count * 0.8, 4.0)
            endpoint_doc = await db["endpoints"].find_one({"_id": endpoint_id})
            if endpoint_doc:
                current_risk = endpoint_doc.get("risk_score", 5.0)
                new_risk = min(current_risk + risk_bump, 10.0)
                risk_factors = endpoint_doc.get("risk_factors", [])
                if critical_count > 0 and "critical_vulns_confirmed" not in risk_factors:
                    risk_factors.append("critical_vulns_confirmed")
                if high_count > 0 and "high_vulns_confirmed" not in risk_factors:
                    risk_factors.append("high_vulns_confirmed")
                await db["endpoints"].update_one(
                    {"_id": endpoint_id},
                    {"$set": {
                        "risk_score": new_risk,
                        "risk_factors": risk_factors,
                        "updated_at": now,
                    }},
                )

        logger.info(
            "Attack %s completed: %d findings (%d critical, %d high)",
            attack_id, len(engine.results), critical_count, high_count,
        )

    except Exception:
        logger.exception("Attack %s failed", attack_id)
        now = datetime.now(timezone.utc).isoformat()
        await db["analyses"].update_one(
            {"endpoint_id": endpoint_id},
            {"$set": {"testing.status": "failed", "updated_at": now}},
        )
        await _append_log(attack_id, {
            "type": "REASONING",
            "content": "Attack failed due to an internal error.",
            "severity": "info",
            "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S"),
        })

    finally:
        await _mark_done(attack_id)
        await release_slot("attack")
