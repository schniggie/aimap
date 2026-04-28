"""Nuclei CLI integration for the AIMap Discovery Engine.

Wraps the ``nuclei`` binary as an async subprocess, parses JSONL output, and
normalizes findings into ``AgentEndpoint``-compatible dicts.

Prerequisites
-------------
* The ``nuclei`` binary must be installed and available on ``$PATH``.
  Install via: ``go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest``
* Custom AIMap templates live under ``templates/`` in the project root.

Usage
-----
::

    runner = NucleiRunner()
    if not runner.check_nuclei():
        raise RuntimeError("nuclei not found")

    findings = await runner.run_scan(
        targets_file="/tmp/alive.txt",
        templates_dir="templates/",
        output_file="/tmp/findings.jsonl",
    )
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Default timeout for a nuclei scan (10 minutes).
DEFAULT_TIMEOUT_SECONDS = 600


class NucleiRunner:
    """Wrapper around the nuclei CLI for agent-protocol detection scans.

    Parameters
    ----------
    binary_path:
        Explicit path to the ``nuclei`` binary.  When ``None`` the binary is
        located via ``shutil.which("nuclei")``.
    timeout:
        Maximum wall-clock time (seconds) for a single scan invocation.
    """

    def __init__(
        self,
        binary_path: str | None = None,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._binary = binary_path or shutil.which("nuclei")
        # Fallback: check common Go bin paths
        if not self._binary:
            import os
            for candidate in [
                Path.home() / "go" / "bin" / "nuclei",
                Path("/usr/local/go/bin/nuclei"),
            ]:
                if candidate.is_file():
                    self._binary = str(candidate)
                    break
        self._timeout = timeout

    # -- Pre-flight checks ---------------------------------------------------

    def check_nuclei(self) -> bool:
        """Return ``True`` if the nuclei binary is available.

        Also logs the detected path for debugging.
        """
        if self._binary and Path(self._binary).is_file():
            logger.info("nuclei binary found at %s", self._binary)
            return True

        # Try shutil.which as a fallback (binary_path may have been a stale
        # explicit path).
        found = shutil.which("nuclei")
        if found:
            self._binary = found
            logger.info("nuclei binary found at %s", found)
            return True

        logger.warning("nuclei binary not found on $PATH")
        return False

    # -- Scan execution ------------------------------------------------------

    async def run_scan(
        self,
        targets_file: str,
        templates_dir: str,
        output_file: str,
        *,
        extra_args: list[str] | None = None,
    ) -> list[dict]:
        """Run nuclei against a target list and return parsed findings.

        Parameters
        ----------
        targets_file:
            Path to a newline-delimited file of target URLs or IPs.
        templates_dir:
            Directory containing YAML nuclei templates.
        output_file:
            Path where nuclei writes its JSONL output (``-jsonl``).
        extra_args:
            Additional CLI flags to pass to nuclei.

        Returns
        -------
        list[dict]
            Parsed finding dicts from the JSONL output.

        Raises
        ------
        FileNotFoundError
            If the nuclei binary is not available.
        RuntimeError
            If the scan process exits with a non-zero code.
        asyncio.TimeoutError
            If the scan exceeds the configured timeout.
        """
        if not self._binary:
            raise FileNotFoundError(
                "nuclei binary not found. Install it or pass binary_path= to NucleiRunner()."
            )

        targets_path = Path(targets_file)
        if not targets_path.is_file():
            raise FileNotFoundError(f"Targets file not found: {targets_file}")

        templates_path = Path(templates_dir)
        if not templates_path.is_dir():
            raise FileNotFoundError(f"Templates directory not found: {templates_dir}")

        cmd = [
            self._binary,
            "-l", str(targets_path),
            "-t", str(templates_path),
            "-jsonl",
            "-o", output_file,
            "-silent",
        ]
        if extra_args:
            cmd.extend(extra_args)

        logger.info("Running nuclei: %s", " ".join(cmd))

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self._timeout,
            )
        except asyncio.TimeoutError:
            logger.error("Nuclei scan timed out after %ds, killing process", self._timeout)
            process.kill()
            await process.wait()
            raise

        if process.returncode != 0:
            stderr_text = stderr.decode(errors="replace").strip()
            logger.error("Nuclei exited with code %d: %s", process.returncode, stderr_text)
            raise RuntimeError(
                f"Nuclei exited with code {process.returncode}: {stderr_text}"
            )

        return self._parse_jsonl(output_file)

    # -- Output parsing ------------------------------------------------------

    @staticmethod
    def _parse_jsonl(output_file: str) -> list[dict]:
        """Parse a nuclei JSONL output file into a list of finding dicts."""
        findings: list[dict] = []
        output_path = Path(output_file)

        if not output_path.is_file():
            logger.warning("Nuclei output file not found: %s", output_file)
            return findings

        with output_path.open("r", encoding="utf-8", errors="replace") as fh:
            for line_no, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    finding = json.loads(line)
                    findings.append(finding)
                except json.JSONDecodeError:
                    logger.warning(
                        "Skipping malformed JSON on line %d of %s",
                        line_no,
                        output_file,
                    )

        logger.info("Parsed %d findings from %s", len(findings), output_file)
        return findings

    # -- Normalization -------------------------------------------------------

    def normalize_finding(self, finding: dict) -> dict:
        """Convert a single Nuclei JSONL finding to an AgentEndpoint-compatible dict.

        Nuclei JSONL structure (abbreviated)::

            {
                "template-id": "mcp-server-detect",
                "info": {
                    "name": "MCP Server Detection",
                    "severity": "info",
                    "tags": ["mcp", "agent"],
                },
                "type": "http",
                "host": "http://104.21.32.50:8080",
                "matched-at": "http://104.21.32.50:8080/",
                "ip": "104.21.32.50",
                "port": "8080",
                "timestamp": "2026-03-14T08:05:00.000Z",
                "matcher-name": "mcp-capabilities",
                "extracted-results": ["..."],
                "curl-command": "curl ...",
            }

        Parameters
        ----------
        finding:
            A single parsed finding dict from Nuclei JSONL output.

        Returns
        -------
        dict
            An AgentEndpoint-compatible dict.
        """
        host = finding.get("host", "")
        ip = finding.get("ip", "")
        port_raw = finding.get("port", "")
        port = int(port_raw) if port_raw else self._extract_port_from_host(host)

        template_id = finding.get("template-id", "")
        info = finding.get("info", {})
        severity = info.get("severity", "info")
        tags = info.get("tags", [])
        timestamp = finding.get("timestamp", datetime.now(timezone.utc).isoformat())

        # Detect protocol from template id / tags
        protocol = self._detect_protocol_from_template(template_id, tags)

        # Build source record
        source_record = {
            "source": "nuclei",
            "template": template_id,
            "discovered_at": timestamp,
            "raw_data": finding,
        }

        return {
            "ip": ip,
            "port": port,
            "hostname": "",
            "url": host,
            "protocol": protocol,
            "auth_status": "unknown",
            "geo": {},
            "server": {},
            "sources": [source_record],
        }

    @staticmethod
    def _extract_port_from_host(host: str) -> int:
        """Best-effort port extraction from a URL string."""
        if not host:
            return 0
        # Strip scheme
        no_scheme = host.split("://", 1)[-1]
        # Check for explicit port
        if ":" in no_scheme:
            port_str = no_scheme.rsplit(":", 1)[-1].split("/")[0]
            try:
                return int(port_str)
            except ValueError:
                pass
        # Infer from scheme
        if host.startswith("https"):
            return 443
        return 80

    @staticmethod
    def _detect_protocol_from_template(template_id: str, tags: list[str]) -> str:
        """Infer AgentEndpoint protocol from nuclei template metadata."""
        combined = (template_id + " " + " ".join(tags)).lower()

        if "mcp" in combined:
            return "mcp"
        if "openai" in combined:
            return "openai_compat"
        if "langserve" in combined:
            return "langserve"
        if "autogen" in combined:
            return "autogen"

        return "mcp"

    # -- Grouped normalization -----------------------------------------------

    @classmethod
    def normalize_findings_group(cls, findings: list[dict]) -> dict:
        """Merge multiple Nuclei findings for the same (ip, port) into one endpoint dict.

        Nuclei emits one JSONL line per extractor match so a single target can
        produce many findings (server-name, tool-list, capabilities, etc.).  This
        method groups them and extracts all relevant fields.

        Parameters
        ----------
        findings:
            A list of parsed Nuclei JSONL dicts that all share the same (ip, port).

        Returns
        -------
        dict
            An AgentEndpoint-compatible dict with tools, framework, auth_status, etc.
        """
        if not findings:
            return {}

        # Grab identity from first finding
        first = findings[0]
        host = first.get("host", "")
        ip = first.get("ip", "")
        port_raw = first.get("port", "")
        port = int(port_raw) if port_raw else cls._extract_port_from_host(host)

        template_id = first.get("template-id", "")
        info = first.get("info", {})
        tags = info.get("tags", [])
        protocol = cls._detect_protocol_from_template(template_id, tags)

        framework = ""
        auth_status = "unknown"
        tools: list[dict] = []
        tool_count = 0
        tool_names: list[str] = []
        capabilities: dict = {}
        metadata: dict = {}
        server_header = ""
        system_prompt = ""
        system_prompt_extracted = False
        source_records: list[dict] = []

        for finding in findings:
            extractor_name = finding.get("extractor-name", "")
            extracted = finding.get("extracted-results", [])
            response = finding.get("response", "")
            ts = finding.get("timestamp", datetime.now(timezone.utc).isoformat())

            # Build source record for each finding
            source_records.append({
                "source": "nuclei",
                "template": finding.get("template-id", template_id),
                "discovered_at": ts,
                "raw_data": finding,
            })

            # ── Extract by extractor name ──────────────────────────
            if extractor_name == "server-name" and extracted:
                framework = extracted[0]

            elif extractor_name == "protocol-version" and extracted:
                metadata["protocol_version"] = extracted[0]

            elif extractor_name == "capabilities" and extracted:
                try:
                    capabilities = json.loads(extracted[0])
                except (json.JSONDecodeError, IndexError):
                    capabilities = {}

            elif extractor_name == "tool-count" and extracted:
                try:
                    tool_count = int(extracted[0])
                except (ValueError, IndexError):
                    pass

            elif extractor_name == "tool-list" and extracted:
                try:
                    raw_tools = json.loads(extracted[0])
                    if isinstance(raw_tools, list):
                        seen_names: set[str] = {t["name"] for t in tools}
                        for t in raw_tools:
                            if isinstance(t, dict):
                                t_name = t.get("name", "")
                                if t_name in seen_names:
                                    continue
                                seen_names.add(t_name)
                                t_desc = t.get("description", "")
                                t_params = t.get("inputSchema", {})
                                t_annotations = t.get("annotations", {})
                                risk, risk_reason = cls._assess_tool_risk(
                                    t_name, t_desc, t_annotations
                                )
                                tools.append({
                                    "name": t_name,
                                    "description": t_desc,
                                    "parameters": t_params,
                                    "risk": risk,
                                    "risk_reason": risk_reason,
                                })
                except (json.JSONDecodeError, IndexError):
                    pass

            elif extractor_name == "tool-names" and extracted:
                # Fallback: just a list of tool name strings
                try:
                    parsed_names = json.loads(extracted[0])
                    if isinstance(parsed_names, list):
                        tool_names = [str(n) for n in parsed_names]
                except (json.JSONDecodeError, IndexError):
                    tool_names = [str(n) for n in extracted]

            # ── Parse the HTTP response field ──────────────────────
            if response:
                parsed = cls._parse_http_response(response)
                if parsed.get("server_header") and not server_header:
                    server_header = parsed["server_header"]
                if parsed.get("auth_status") != "unknown":
                    auth_status = parsed["auth_status"]
                if parsed.get("system_prompt"):
                    system_prompt = parsed["system_prompt"]
                    system_prompt_extracted = True

        # ── Fallback: if no tool-list but tool-names, create stubs ─
        if not tools and tool_names:
            for name in tool_names:
                risk, risk_reason = cls._assess_tool_risk(name, "", {})
                tools.append({
                    "name": name,
                    "description": "",
                    "parameters": {},
                    "risk": risk,
                    "risk_reason": risk_reason,
                })

        if tools and not tool_count:
            tool_count = len(tools)

        # Build the TLS flag from url
        tls = host.startswith("https")

        return {
            "ip": ip,
            "port": port,
            "hostname": "",
            "url": host,
            "protocol": protocol,
            "framework": framework,
            "auth_status": auth_status,
            "tools": tools,
            "tool_count": tool_count,
            "capabilities": capabilities,
            "metadata": metadata,
            "system_prompt": system_prompt,
            "system_prompt_extracted": system_prompt_extracted,
            "geo": {},
            "server": {
                "banner": server_header,
                "headers": {},
                "tls": tls,
                "cors_open": False,
            },
            "sources": source_records,
            "risk_score": 0.0,
            "risk_factors": [],
            "dangerous_combos": [],
            "tags": [],
        }

    @staticmethod
    def _parse_http_response(response: str) -> dict:
        """Parse the raw HTTP response string from a Nuclei finding.

        Extracts:
        - Server header
        - Auth status from HTTP status codes (401/403)
        - JSON body for MCP initialize responses
        - System prompt if leaked in body

        Parameters
        ----------
        response:
            The full HTTP response string (status line + headers + body).

        Returns
        -------
        dict
            Extracted fields: server_header, auth_status, body_json, system_prompt
        """
        result: dict[str, Any] = {
            "server_header": "",
            "auth_status": "unknown",
            "body_json": None,
            "system_prompt": "",
        }

        if not response:
            return result

        # Split headers and body
        parts = response.split("\r\n\r\n", 1)
        if len(parts) < 2:
            parts = response.split("\n\n", 1)

        header_block = parts[0] if parts else ""
        body = parts[1] if len(parts) > 1 else ""

        # Extract Server header
        for line in header_block.split("\n"):
            line_stripped = line.strip()
            if line_stripped.lower().startswith("server:"):
                result["server_header"] = line_stripped.split(":", 1)[1].strip()
                break

        # Check for auth-related status codes
        first_line = header_block.split("\n", 1)[0] if header_block else ""
        if " 401 " in first_line or " 403 " in first_line:
            result["auth_status"] = "api_key"
        elif " 200 " in first_line:
            result["auth_status"] = "none"

        # Parse JSON body
        if body.strip():
            try:
                body_json = json.loads(body.strip())
                result["body_json"] = body_json

                # Check for system prompt in MCP responses
                if isinstance(body_json, dict):
                    # MCP initialize response may contain server info
                    instructions = body_json.get("result", {}).get("instructions", "")
                    if instructions:
                        result["system_prompt"] = instructions
            except json.JSONDecodeError:
                pass

        return result

    @staticmethod
    def _assess_tool_risk(
        tool_name: str,
        tool_description: str,
        annotations: dict,
    ) -> tuple[str, str]:
        """Assess the risk level of a tool based on its name, description, and annotations.

        Parameters
        ----------
        tool_name:
            The name of the tool.
        tool_description:
            The description of the tool.
        annotations:
            MCP tool annotations dict (may contain destructiveHint, readOnlyHint, etc.)

        Returns
        -------
        tuple[str, str]
            (risk_level, risk_reason) where risk_level is one of
            critical/high/medium/low/info.
        """
        # Check annotations first -- they are authoritative
        if annotations:
            if annotations.get("destructiveHint") is True:
                return ("high", "Tool annotated as destructive")
            if annotations.get("readOnlyHint") is True:
                return ("info", "Tool annotated as read-only")

        combined = f"{tool_name} {tool_description}".lower()

        # Critical patterns
        critical_patterns = [
            "exec", "shell", "run_command", "eval", "sql.*write",
            "delete_all", "admin", "deploy",
        ]
        for pat in critical_patterns:
            if re.search(pat, combined):
                return ("critical", f"Matches critical pattern: {pat}")

        # High patterns
        high_patterns = [
            "write", "update", "delete", "send_email", "transfer",
            "modify", "create_user",
        ]
        for pat in high_patterns:
            if re.search(pat, combined):
                return ("high", f"Matches high-risk pattern: {pat}")

        # Medium patterns
        medium_patterns = ["upload", "download", "create", "post"]
        for pat in medium_patterns:
            if re.search(pat, combined):
                return ("medium", f"Matches medium-risk pattern: {pat}")

        # Low patterns
        low_patterns = ["search", "query", "get", "list", "read", "fetch"]
        for pat in low_patterns:
            if re.search(pat, combined):
                return ("low", f"Matches low-risk pattern: {pat}")

        return ("info", "No risk indicators detected")

    @classmethod
    def group_findings_by_target(cls, findings: list[dict]) -> dict[tuple[str, int], list[dict]]:
        """Group a list of Nuclei findings by (ip, port).

        Parameters
        ----------
        findings:
            A list of parsed Nuclei JSONL dicts.

        Returns
        -------
        dict
            Mapping of (ip, port) to list of findings for that target.
        """
        groups: dict[tuple[str, int], list[dict]] = defaultdict(list)
        for f in findings:
            ip = f.get("ip", "")
            port_raw = f.get("port", "")
            try:
                port = int(port_raw) if port_raw else cls._extract_port_from_host(f.get("host", ""))
            except (ValueError, TypeError):
                port = 0
            groups[(ip, port)].append(f)
        return dict(groups)
