"""Scan Orchestrator for the AIMap Discovery Engine.

Coordinates the full scanning pipeline:

1. **Ingestion scans** -- use a ``SourceAdapter`` to search a 3P source
   (Shodan, Censys, ...) and upsert results into MongoDB.
2. **Active scans** -- write target IPs to a temp file, run httpx for an
   alive-host sweep, then run Nuclei with custom templates, normalize
   findings, and upsert to MongoDB.

The orchestrator reports progress via an optional ``progress_callback`` so
that the API layer can push updates to the frontend over WebSocket.
"""

from __future__ import annotations

import asyncio
import json
import logging
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Coroutine

from app.discovery.base import SourceAdapter
from app.discovery.nuclei_runner import NucleiRunner
from app.discovery.shodan_adapter import AGENT_QUERIES, ShodanAdapter

logger = logging.getLogger(__name__)

# Registry of available source adapters.  Extend as new adapters are added.
_ADAPTER_REGISTRY: dict[str, type[SourceAdapter]] = {
    "shodan": ShodanAdapter,
}

# Default ports to probe during an active scan.
DEFAULT_PORTS = [80, 443, 3000, 8000, 8080, 8443, 8888]

# Type alias for the progress callback.
ProgressCallback = Callable[[dict[str, Any]], Coroutine[Any, Any, None]]


class ScanOrchestrator:
    """Coordinates discovery scans (3P ingestion and active scanning).

    Parameters
    ----------
    nuclei_runner:
        A pre-configured ``NucleiRunner`` instance.  When ``None`` one is
        created with default settings.
    templates_dir:
        Path to the directory containing AIMap Nuclei templates.
        Defaults to ``<project_root>/templates``.
    """

    def __init__(
        self,
        nuclei_runner: NucleiRunner | None = None,
        templates_dir: str | None = None,
    ) -> None:
        self._nuclei = nuclei_runner or NucleiRunner()
        # Resolve templates dir relative to project root
        if templates_dir:
            self._templates_dir = templates_dir
        else:
            # Assume: backend/app/discovery/orchestrator.py -> project root is ../../../
            project_root = Path(__file__).resolve().parents[3]
            self._templates_dir = str(project_root / "templates")

    # -- Public API ----------------------------------------------------------

    async def run_scan(
        self,
        scan_config: dict[str, Any],
        db: Any,
        progress_callback: ProgressCallback | None = None,
    ) -> dict[str, Any]:
        """Execute a scan based on the provided configuration.

        Parameters
        ----------
        scan_config:
            Dict with at minimum a ``type`` key (``"ingestion"`` or ``"active"``).
            For ingestion scans: ``source``, ``query``, ``max_results``.
            For active scans: ``target`` (CIDR or host list), ``ports``,
            ``templates``.
        db:
            An ``AsyncIOMotorDatabase`` instance.
        progress_callback:
            Optional async callable that receives progress dicts.

        Returns
        -------
        dict
            Summary of the scan results.
        """
        scan_type = scan_config.get("type", "ingestion")

        if scan_type == "ingestion":
            return await self._run_ingestion_scan(scan_config, db, progress_callback)
        elif scan_type == "active":
            return await self._run_active_scan(scan_config, db, progress_callback)
        else:
            raise ValueError(f"Unknown scan type: {scan_type!r}")

    async def run_3p_ingest(
        self,
        source: str,
        query: str,
        max_results: int,
        db: Any,
    ) -> list[str]:
        """Convenience method for third-party ingestion.

        Parameters
        ----------
        source:
            Adapter name (e.g. ``"shodan"``).
        query:
            Search query in the source's native syntax.
        max_results:
            Upper bound on results.
        db:
            ``AsyncIOMotorDatabase`` instance.

        Returns
        -------
        list[str]
            List of upserted endpoint ``_id`` values.
        """
        adapter = self._get_adapter(source)
        return await adapter.ingest(query, max_results, db)

    # -- Ingestion scan ------------------------------------------------------

    async def _run_ingestion_scan(
        self,
        config: dict[str, Any],
        db: Any,
        progress_callback: ProgressCallback | None,
    ) -> dict[str, Any]:
        """Run a 3P ingestion scan with multiple preconfigured queries.

        Config keys
        -----------
        source : str
            Adapter name (default ``"shodan"``).
        queries : list[str] | None
            Subset of ``AGENT_QUERIES`` keys to run (e.g. ``["mcp", "openai_compat"]``).
            When ``None`` or empty, **all** predefined queries are run.
        target : str | None
            Optional CIDR to scope the search (added as Shodan ``net:`` filter).
        max_results_per_query : int
            Upper bound per individual query (default 100).
        """
        source = config.get("source", "shodan")
        target_cidr = config.get("target", "")
        max_per_query = config.get("max_results_per_query", config.get("max_results", 100))

        # Determine which queries to run
        requested = config.get("queries") or []
        if requested:
            queries = {k: v for k, v in AGENT_QUERIES.items() if k in requested}
            # Warn about unknown keys
            unknown = set(requested) - set(AGENT_QUERIES.keys())
            if unknown:
                logger.warning("Unknown query keys ignored: %s", unknown)
        else:
            queries = dict(AGENT_QUERIES)

        if not queries:
            logger.warning("No queries to run for ingestion scan")
            return {
                "type": "ingestion",
                "source": source,
                "queries_run": [],
                "endpoint_ids": [],
                "total_endpoints": 0,
            }

        if progress_callback:
            await progress_callback({
                "phase": "ingestion",
                "status": "started",
                "source": source,
                "query_count": len(queries),
                "target": target_cidr or "global",
            })

        all_endpoint_ids: list[str] = []
        queries_run: list[dict[str, Any]] = []

        for query_key, base_query in queries.items():
            # Scope to CIDR if provided
            full_query = f"net:{target_cidr} {base_query}" if target_cidr else base_query

            if progress_callback:
                await progress_callback({
                    "phase": "ingestion",
                    "status": "running_query",
                    "query_key": query_key,
                    "query": full_query,
                    "queries_completed": len(queries_run),
                    "queries_total": len(queries),
                })

            try:
                ids = await self.run_3p_ingest(source, full_query, max_per_query, db)
                all_endpoint_ids.extend(ids)
                queries_run.append({
                    "key": query_key,
                    "query": full_query,
                    "endpoints_found": len(ids),
                })
                logger.info(
                    "Ingestion query %s found %d endpoints (query=%r)",
                    query_key, len(ids), full_query,
                )
            except Exception:
                logger.exception("Ingestion query %s failed", query_key)
                queries_run.append({
                    "key": query_key,
                    "query": full_query,
                    "endpoints_found": 0,
                    "error": True,
                })

        # Deduplicate (same endpoint may match multiple queries)
        unique_ids = list(dict.fromkeys(all_endpoint_ids))

        if progress_callback:
            await progress_callback({
                "phase": "ingestion",
                "status": "completed",
                "source": source,
                "endpoints_found": len(unique_ids),
                "queries_run": len(queries_run),
            })

        return {
            "type": "ingestion",
            "source": source,
            "target": target_cidr or "global",
            "queries_run": queries_run,
            "endpoint_ids": unique_ids,
            "total_endpoints": len(unique_ids),
        }

    # -- Active scan ---------------------------------------------------------

    async def _run_active_scan(
        self,
        config: dict[str, Any],
        db: Any,
        progress_callback: ProgressCallback | None,
    ) -> dict[str, Any]:
        """Run an active scan: httpx alive sweep -> Nuclei detection."""
        target = config.get("target", "")
        ports = config.get("ports", DEFAULT_PORTS)
        scan_id = config.get("scan_id", f"scan_{uuid.uuid4().hex[:12]}")

        if not target:
            raise ValueError("Active scan requires a 'target' (CIDR or host list)")

        # Step 1: Write targets to temp file
        if progress_callback:
            await progress_callback({
                "phase": "httpx",
                "status": "started",
                "target": target,
            })

        alive_hosts = await self._run_httpx_sweep(target, ports)

        if progress_callback:
            await progress_callback({
                "phase": "httpx",
                "status": "completed",
                "alive_count": len(alive_hosts),
            })

        if not alive_hosts:
            logger.info("No alive hosts found for target: %s", target)
            return {
                "type": "active",
                "scan_id": scan_id,
                "target": target,
                "alive_count": 0,
                "endpoint_ids": [],
                "total_endpoints": 0,
            }

        # Step 2: Write alive hosts to temp file for Nuclei
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, prefix="aimap_alive_"
        ) as alive_file:
            for host in alive_hosts:
                alive_file.write(host + "\n")
            alive_path = alive_file.name

        # Step 3: Run Nuclei
        if progress_callback:
            await progress_callback({
                "phase": "nuclei",
                "status": "started",
                "target_count": len(alive_hosts),
            })

        output_path = tempfile.mktemp(suffix=".jsonl", prefix="aimap_findings_")

        try:
            findings = await self._nuclei.run_scan(
                targets_file=alive_path,
                templates_dir=self._templates_dir,
                output_file=output_path,
            )
        except (FileNotFoundError, RuntimeError) as exc:
            logger.error("Nuclei scan failed: %s", exc)
            findings = []

        if progress_callback:
            await progress_callback({
                "phase": "nuclei",
                "status": "completed",
                "findings_count": len(findings),
            })

        # Step 4: Normalize and upsert findings
        endpoint_ids: list[str] = []
        collection = db["endpoints"]

        for finding in findings:
            try:
                normalized = self._nuclei.normalize_finding(finding)
                normalized.setdefault("sources", [{}])[0]["scan_id"] = scan_id

                # Use the base adapter upsert logic
                adapter = ShodanAdapter.__new__(ShodanAdapter)
                doc_id = await SourceAdapter._upsert(adapter, collection, normalized)
                endpoint_ids.append(doc_id)
            except Exception:
                logger.exception("Failed to upsert nuclei finding")

        # Cleanup temp files
        for path in [alive_path, output_path]:
            try:
                Path(path).unlink(missing_ok=True)
            except OSError:
                pass

        if progress_callback:
            await progress_callback({
                "phase": "complete",
                "status": "completed",
                "total_endpoints": len(endpoint_ids),
            })

        return {
            "type": "active",
            "scan_id": scan_id,
            "target": target,
            "alive_count": len(alive_hosts),
            "findings_count": len(findings),
            "endpoint_ids": endpoint_ids,
            "total_endpoints": len(endpoint_ids),
        }

    # -- httpx alive sweep ---------------------------------------------------

    async def _run_httpx_sweep(
        self,
        target: str,
        ports: list[int],
    ) -> list[str]:
        """Run httpx to discover alive HTTP hosts.

        Parameters
        ----------
        target:
            CIDR range or single host.
        ports:
            List of ports to probe.

        Returns
        -------
        list[str]
            Alive host URLs (e.g. ``["http://1.2.3.4:8080"]``).
        """
        # Use ProjectDiscovery httpx (not Python httpx)
        httpx_binary = str(Path.home() / "go" / "bin" / "httpx")
        if not Path(httpx_binary).is_file():
            import shutil
            httpx_binary = shutil.which("httpx") or "httpx"
            logger.warning("PD httpx not at ~/go/bin/httpx, falling back to: %s", httpx_binary)

        ports_str = ",".join(str(p) for p in ports)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, prefix="aimap_httpx_"
        ) as output_file:
            output_path = output_file.name

        # Write target to a temp file for safe input (avoid shell injection)
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, prefix="aimap_targets_"
        ) as tf:
            tf.write(target + "\n")
            targets_path = tf.name

        try:
            process = await asyncio.create_subprocess_exec(
                httpx_binary,
                "-l", targets_path,
                "-ports", ports_str,
                "-json",
                "-o", output_path,
                "-silent",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(process.communicate(), timeout=300)
        except FileNotFoundError:
            logger.error("httpx binary not found on $PATH")
            return []
        except asyncio.TimeoutError:
            logger.error("httpx sweep timed out")
            process.kill()
            await process.wait()
            return []
        except Exception:
            logger.exception("httpx sweep failed")
            return []
        finally:
            # Cleanup the targets file
            try:
                Path(targets_path).unlink(missing_ok=True)
            except OSError:
                pass

        # Parse httpx JSON output
        alive: list[str] = []
        output = Path(output_path)
        if output.is_file():
            with output.open("r") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        url = data.get("url", "")
                        if url:
                            alive.append(url)
                    except json.JSONDecodeError:
                        continue
            output.unlink(missing_ok=True)

        logger.info("httpx found %d alive hosts for target %s", len(alive), target)
        return alive

    # -- Helpers -------------------------------------------------------------

    @staticmethod
    def _get_adapter(source: str) -> SourceAdapter:
        """Instantiate and return a source adapter by name."""
        adapter_cls = _ADAPTER_REGISTRY.get(source)
        if adapter_cls is None:
            raise ValueError(
                f"Unknown source adapter: {source!r}. "
                f"Available: {list(_ADAPTER_REGISTRY.keys())}"
            )
        return adapter_cls()
