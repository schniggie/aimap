"""Base adapter interface for the AIMap Discovery Engine.

Every third-party data source (Shodan, Censys, FOFA, ZoomEye) implements the
``SourceAdapter`` abstract base class defined here.  The adapter is responsible
for three things:

1. **search** -- query the upstream source and yield raw result dicts.
2. **normalize** -- convert one raw result dict into an ``AgentEndpoint``-
   compatible dict (matching the schema in ``app.models.endpoint``).
3. **ingest** -- the full pipeline: search -> normalize -> upsert to MongoDB,
   returning a list of endpoint IDs that were created or updated.

Upsert logic
-------------
On ingest the adapter looks up existing documents by ``(ip, port)``.  If a
document already exists:

* The new source entry is appended to ``sources`` (unless an entry for the
  same source already exists, in which case it is replaced).
* ``last_seen`` and ``updated_at`` are bumped to *now*.
* Top-level fields are updated only when the incoming data is richer (i.e. the
  incoming value is truthy and the existing value is falsy/empty).

If no document exists a fresh one is inserted.
"""

from __future__ import annotations

import logging
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, AsyncIterator

logger = logging.getLogger(__name__)


class SourceAdapter(ABC):
    """Abstract base class that all discovery source adapters must implement.

    Subclasses **must** provide:

    * ``source_name`` -- a short identifier such as ``"shodan"`` or ``"censys"``.
    * ``search()`` -- async generator that yields raw results from the source.
    * ``normalize()`` -- synchronous converter from a raw result dict to an
      ``AgentEndpoint``-compatible dict.

    The ``ingest()`` method is provided by this base class and orchestrates the
    full search-normalize-upsert pipeline.
    """

    # -- Properties ----------------------------------------------------------

    @property
    @abstractmethod
    def source_name(self) -> str:
        """Short identifier for this source (e.g. ``"shodan"``)."""
        ...

    # -- Abstract methods ----------------------------------------------------

    @abstractmethod
    async def search(self, query: str, max_results: int = 100) -> AsyncIterator[dict]:
        """Yield raw result dicts from the upstream source.

        Parameters
        ----------
        query:
            The search query in the source's native syntax.
        max_results:
            Upper bound on the number of results to return.

        Yields
        ------
        dict
            A raw result dict as returned by the source API.
        """
        ...
        # Make the method an async generator so subclasses can use ``yield``.
        yield  # pragma: no cover

    @abstractmethod
    def normalize(self, raw: dict) -> dict:
        """Convert a raw source result into an AgentEndpoint-compatible dict.

        The returned dict should contain at minimum ``ip``, ``port``, and
        ``protocol``.  All other fields are optional and will be filled with
        defaults during upsert if absent.

        Parameters
        ----------
        raw:
            A single raw result dict as yielded by ``search()``.

        Returns
        -------
        dict
            A dict whose keys match the ``AgentEndpoint`` schema.
        """
        ...

    # -- Concrete pipeline ---------------------------------------------------

    async def ingest(
        self,
        query: str,
        max_results: int,
        db: Any,
    ) -> list[str]:
        """Full pipeline: search, normalize, upsert to MongoDB.

        Parameters
        ----------
        query:
            Search query forwarded to ``search()``.
        max_results:
            Maximum results forwarded to ``search()``.
        db:
            An ``AsyncIOMotorDatabase`` instance (or compatible mock).

        Returns
        -------
        list[str]
            The ``_id`` values of every upserted endpoint document.
        """
        collection = db["endpoints"]
        endpoint_ids: list[str] = []

        async for raw in self.search(query, max_results):
            try:
                normalized = self.normalize(raw)
            except Exception:
                logger.exception("Failed to normalize result from %s", self.source_name)
                continue

            ip = normalized.get("ip")
            port = normalized.get("port")
            if not ip or not port:
                logger.warning("Skipping result with missing ip/port from %s", self.source_name)
                continue

            doc_id = await self._upsert(collection, normalized)
            endpoint_ids.append(doc_id)

        logger.info(
            "Ingested %d endpoints from %s (query=%r)",
            len(endpoint_ids),
            self.source_name,
            query,
        )
        return endpoint_ids

    # -- Upsert helper -------------------------------------------------------

    async def _upsert(self, collection: Any, normalized: dict) -> str:
        """Insert or merge a normalized endpoint dict into MongoDB.

        Returns the ``_id`` of the upserted document.
        """
        ip = normalized["ip"]
        port = normalized["port"]
        now = datetime.now(timezone.utc)

        existing = await collection.find_one({"ip": ip, "port": port})

        if existing is not None:
            return await self._merge_existing(collection, existing, normalized, now)

        return await self._insert_new(collection, normalized, now)

    async def _insert_new(self, collection: Any, normalized: dict, now: datetime) -> str:
        """Insert a brand-new endpoint document."""
        doc_id = f"ep_{uuid.uuid4().hex[:12]}"

        doc = {
            "_id": doc_id,
            "ip": normalized["ip"],
            "port": normalized["port"],
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
        logger.debug("Inserted new endpoint %s for %s:%s", doc_id, doc["ip"], doc["port"])
        return doc_id

    async def _merge_existing(
        self,
        collection: Any,
        existing: dict,
        normalized: dict,
        now: datetime,
    ) -> str:
        """Merge incoming data into an existing endpoint document."""
        doc_id: str = existing["_id"]
        update_set: dict[str, Any] = {
            "last_seen": now.isoformat(),
            "updated_at": now.isoformat(),
        }

        # Update top-level fields only when incoming data is richer.
        _MERGE_FIELDS = [
            "hostname", "url", "framework", "model", "protocol",
        ]
        for field in _MERGE_FIELDS:
            incoming = normalized.get(field)
            current = existing.get(field)
            if incoming and not current:
                update_set[field] = incoming

        # Merge geo: update if incoming geo has more data.
        incoming_geo = normalized.get("geo", {})
        current_geo = existing.get("geo", {})
        if incoming_geo and not current_geo.get("country"):
            update_set["geo"] = incoming_geo

        # Merge server info: update if incoming has more data.
        incoming_server = normalized.get("server", {})
        current_server = existing.get("server", {})
        if incoming_server.get("banner") and not current_server.get("banner"):
            update_set["server"] = incoming_server

        # Merge tools: update if incoming has tools and current doesn't, or incoming has more
        incoming_tools = normalized.get("tools", [])
        current_tools = existing.get("tools", [])
        if incoming_tools and (not current_tools or len(incoming_tools) > len(current_tools)):
            update_set["tools"] = incoming_tools
            update_set["tool_count"] = normalized.get("tool_count", len(incoming_tools))

        # Merge auth_status: update if incoming is not "unknown" and current IS "unknown"
        incoming_auth = normalized.get("auth_status", "unknown")
        current_auth = existing.get("auth_status", "unknown")
        if incoming_auth != "unknown" and current_auth == "unknown":
            update_set["auth_status"] = incoming_auth

        # Merge risk_score / risk_factors: update if incoming is non-zero and current is zero
        incoming_risk = normalized.get("risk_score", 0.0)
        current_risk = existing.get("risk_score", 0.0)
        if incoming_risk and not current_risk:
            update_set["risk_score"] = incoming_risk
            update_set["risk_factors"] = normalized.get("risk_factors", [])

        # Merge system_prompt: update if incoming has it and current doesn't
        incoming_prompt = normalized.get("system_prompt", "")
        current_prompt = existing.get("system_prompt", "")
        if incoming_prompt and not current_prompt:
            update_set["system_prompt"] = incoming_prompt
            update_set["system_prompt_extracted"] = normalized.get(
                "system_prompt_extracted", bool(incoming_prompt)
            )

        # Merge dangerous_combos: union
        incoming_combos = set(normalized.get("dangerous_combos", []))
        current_combos = set(existing.get("dangerous_combos", []))
        merged_combos = current_combos | incoming_combos
        if merged_combos != current_combos:
            update_set["dangerous_combos"] = list(merged_combos)

        # Merge sources array: append new source or replace existing one.
        incoming_sources = normalized.get("sources", [])
        current_sources: list[dict] = list(existing.get("sources", []))
        for src in incoming_sources:
            # Remove any existing entry for the same source name
            current_sources = [
                s for s in current_sources if s.get("source") != src.get("source")
            ]
            current_sources.append(src)
        update_set["sources"] = current_sources

        await collection.update_one({"_id": doc_id}, {"$set": update_set})
        logger.debug("Merged endpoint %s for %s:%s", doc_id, existing["ip"], existing["port"])
        return doc_id
