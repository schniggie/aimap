"""MCP (Model Context Protocol) JSON-RPC client.

Handles communication with remote MCP servers over HTTP/SSE.
Supports both Streamable HTTP (2025-03-26 spec) and legacy HTTP+SSE transport.

The client sends JSON-RPC 2.0 requests via HTTP POST and handles responses
that may come back as direct JSON or as Server-Sent Events.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

import httpx

logger = logging.getLogger(__name__)

# MCP protocol version we advertise
MCP_PROTOCOL_VERSION = "2024-11-05"

# Timeout for individual requests (seconds)
REQUEST_TIMEOUT = 30.0


@dataclass
class MCPCapabilities:
    """Parsed server capabilities from the initialize response."""

    protocol_version: str = ""
    server_name: str = ""
    server_version: str = ""
    tools: bool = False
    resources: bool = False
    prompts: bool = False
    logging: bool = False
    raw: dict = field(default_factory=dict)


@dataclass
class MCPTool:
    """A tool exposed by the MCP server."""

    name: str
    description: str = ""
    input_schema: dict = field(default_factory=dict)
    annotations: dict = field(default_factory=dict)


class MCPClientError(Exception):
    """Raised when MCP communication fails."""


class MCPClient:
    """JSON-RPC 2.0 client for MCP servers.

    Parameters
    ----------
    base_url:
        The MCP server URL (e.g. ``http://1.2.3.4:8080``).
    mcp_path:
        The MCP endpoint path. Tries common paths if not specified.
    timeout:
        Request timeout in seconds.
    """

    # Common MCP endpoint paths to probe
    COMMON_PATHS = ["/mcp", "/api/mcp", "/sse", "/mcp/sse", "/", "/v1/messages"]

    def __init__(
        self,
        base_url: str,
        mcp_path: str | None = None,
        timeout: float = REQUEST_TIMEOUT,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.mcp_path = mcp_path
        self.timeout = timeout
        self._request_id = 0
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            follow_redirects=True,
            verify=False,  # Many MCP servers use self-signed certs
        )
        self.capabilities: MCPCapabilities | None = None
        self._session_url: str | None = None  # For Streamable HTTP

    async def close(self) -> None:
        await self._client.aclose()

    # -- JSON-RPC helpers ------------------------------------------------

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    def _build_request(self, method: str, params: dict | None = None) -> dict:
        msg: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": method,
        }
        if params:
            msg["params"] = params
        return msg

    async def _send_jsonrpc(
        self,
        url: str,
        method: str,
        params: dict | None = None,
    ) -> dict:
        """Send a JSON-RPC request and return the result.

        Handles both direct JSON responses and SSE-wrapped responses.
        """
        payload = self._build_request(method, params)
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }

        try:
            resp = await self._client.post(url, json=payload, headers=headers)
        except httpx.ConnectError as exc:
            raise MCPClientError(f"Connection failed: {exc}") from exc
        except httpx.TimeoutException as exc:
            raise MCPClientError(f"Request timed out: {exc}") from exc

        content_type = resp.headers.get("content-type", "")

        # Direct JSON response
        if "application/json" in content_type:
            data = resp.json()
            if "error" in data:
                err = data["error"]
                if not isinstance(err, dict):
                    raise MCPClientError(f"JSON-RPC error: {err}")
                raise MCPClientError(
                    f"JSON-RPC error {err.get('code')}: {err.get('message')}"
                )
            return data.get("result", data)

        # SSE response — parse event stream for the result
        if "text/event-stream" in content_type:
            return self._parse_sse_response(resp.text)

        # Some servers just return JSON without proper content-type
        try:
            data = resp.json()
            if isinstance(data, dict):
                if "error" in data:
                    err = data["error"]
                    raise MCPClientError(
                        f"JSON-RPC error {err.get('code')}: {err.get('message')}"
                    )
                return data.get("result", data)
        except (json.JSONDecodeError, ValueError):
            pass

        # Return raw text as a dict for inspection
        return {"_raw_response": resp.text[:2000], "_status_code": resp.status_code}

    @staticmethod
    def _parse_sse_response(text: str) -> dict:
        """Extract JSON-RPC result from SSE event stream."""
        for line in text.split("\n"):
            line = line.strip()
            if line.startswith("data:"):
                data_str = line[5:].strip()
                if not data_str:
                    continue
                try:
                    data = json.loads(data_str)
                    if isinstance(data, dict):
                        if "result" in data:
                            return data["result"]
                        if "error" in data:
                            err = data["error"]
                            raise MCPClientError(
                                f"JSON-RPC error {err.get('code')}: {err.get('message')}"
                            )
                        return data
                except json.JSONDecodeError:
                    continue
        return {"_raw_sse": text[:2000]}

    # -- MCP Protocol methods --------------------------------------------

    async def discover_endpoint(self) -> str:
        """Probe common paths to find the MCP endpoint.

        Returns the working URL path.
        """
        if self.mcp_path:
            return urljoin(self.base_url + "/", self.mcp_path)

        for path in self.COMMON_PATHS:
            url = self.base_url + path
            try:
                resp = await self._client.post(
                    url,
                    json=self._build_request("initialize", {
                        "protocolVersion": MCP_PROTOCOL_VERSION,
                        "capabilities": {},
                        "clientInfo": {"name": "aimap-scanner", "version": "1.0"},
                    }),
                    headers={
                        "Content-Type": "application/json",
                        "Accept": "application/json, text/event-stream",
                    },
                )
                if resp.status_code in (200, 201):
                    text = resp.text.lower()
                    if "jsonrpc" in text or "capabilities" in text or "protocolversion" in text.replace("_", ""):
                        self.mcp_path = path
                        logger.info("Found MCP endpoint at %s", url)
                        return url
            except (httpx.ConnectError, httpx.TimeoutException):
                continue
            except Exception:
                continue

        # Fallback to base URL
        logger.warning("No MCP endpoint found, falling back to %s", self.base_url)
        self.mcp_path = "/"
        return self.base_url

    async def initialize(self) -> MCPCapabilities:
        """Perform the MCP initialize handshake."""
        url = await self.discover_endpoint()
        self._session_url = url

        result = await self._send_jsonrpc(url, "initialize", {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "aimap-scanner", "version": "1.0"},
        })

        caps = MCPCapabilities(raw=result)
        caps.protocol_version = result.get("protocolVersion", "")
        server_info = result.get("serverInfo", {})
        caps.server_name = server_info.get("name", "")
        caps.server_version = server_info.get("version", "")

        cap_dict = result.get("capabilities", {})
        # In MCP, presence of the key means supported (even if value is {})
        caps.tools = "tools" in cap_dict
        caps.resources = "resources" in cap_dict
        caps.prompts = "prompts" in cap_dict
        caps.logging = "logging" in cap_dict

        self.capabilities = caps

        # Send initialized notification
        try:
            await self._client.post(
                url,
                json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                headers={"Content-Type": "application/json"},
            )
        except Exception:
            pass  # Notification failures are non-fatal

        return caps

    async def list_tools(self) -> list[MCPTool]:
        """Call tools/list and return parsed tools."""
        url = self._session_url or await self.discover_endpoint()
        result = await self._send_jsonrpc(url, "tools/list")

        tools_raw = result.get("tools", [])
        if not isinstance(tools_raw, list):
            return []

        tools = []
        for t in tools_raw:
            if not isinstance(t, dict):
                continue
            tools.append(MCPTool(
                name=t.get("name", ""),
                description=t.get("description", ""),
                input_schema=t.get("inputSchema", {}),
                annotations=t.get("annotations", {}),
            ))
        return tools

    async def call_tool(self, name: str, arguments: dict | None = None) -> dict:
        """Call a specific tool and return the result."""
        url = self._session_url or await self.discover_endpoint()
        params: dict[str, Any] = {"name": name}
        if arguments:
            params["arguments"] = arguments
        return await self._send_jsonrpc(url, "tools/call", params)

    async def list_resources(self) -> list[dict]:
        """Call resources/list and return raw resource dicts."""
        url = self._session_url or await self.discover_endpoint()
        result = await self._send_jsonrpc(url, "resources/list")
        return result.get("resources", [])

    async def read_resource(self, uri: str) -> dict:
        """Read a specific resource by URI."""
        url = self._session_url or await self.discover_endpoint()
        return await self._send_jsonrpc(url, "resources/read", {"uri": uri})

    async def list_prompts(self) -> list[dict]:
        """Call prompts/list and return raw prompt dicts."""
        url = self._session_url or await self.discover_endpoint()
        result = await self._send_jsonrpc(url, "prompts/list")
        return result.get("prompts", [])

    async def get_prompt(self, name: str, arguments: dict | None = None) -> dict:
        """Get a specific prompt by name."""
        url = self._session_url or await self.discover_endpoint()
        params: dict[str, Any] = {"name": name}
        if arguments:
            params["arguments"] = arguments
        return await self._send_jsonrpc(url, "prompts/get", params)

    async def raw_request(
        self,
        method: str,
        params: dict | None = None,
    ) -> dict:
        """Send an arbitrary JSON-RPC method (for fuzzing/testing)."""
        url = self._session_url or await self.discover_endpoint()
        return await self._send_jsonrpc(url, method, params)

    # -- Convenience for attack module -----------------------------------

    async def probe_http(self, path: str = "/") -> dict:
        """Simple HTTP GET to the server (non-JSON-RPC)."""
        url = self.base_url + path
        try:
            resp = await self._client.get(url)
            return {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text[:5000],
            }
        except Exception as exc:
            return {"error": str(exc)}
