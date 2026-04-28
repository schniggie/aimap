"""Shodan source adapter for the AIMap Discovery Engine.

Uses the ``shodan`` Python SDK to query the Shodan search engine for exposed
AI agent endpoints (MCP servers, LangServe, OpenAI-compatible APIs, etc.) and
normalizes the results into ``AgentEndpoint``-compatible dicts.

Environment
-----------
Requires ``SHODAN_API_KEY`` to be set.  The key is read from ``app.config``.

Predefined queries
------------------
The adapter ships with a set of curated search queries tuned for discovering
different agent protocols:

* MCP servers -- ``"jsonrpc" "capabilities"``
* OpenAI-compatible -- ``"/v1/models" "openai"``
* LangServe -- ``"/docs" "langserve"``
* Generic agent -- ``"/invoke" "agent"``

Rate limiting
-------------
Shodan's API is rate-limited (1 req/s for the basic plan).  The adapter
respects this by inserting a 1-second delay between paginated search calls.
Transient errors are caught and logged rather than propagated so that a
single bad result never kills the entire ingest pipeline.
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timezone
from typing import Any, AsyncIterator

import shodan

from app.config import settings
from app.discovery.base import SourceAdapter

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Predefined search queries for discovering exposed AI/agent infrastructure.
#
# Each entry maps a short key to a Shodan query string.  When a scan
# includes a CIDR target the orchestrator prepends ``net:<cidr>`` to
# scope the search.
#
# Sources / references:
#   - Knostic MCP-Scanner research
#   - Praetorian Julius LLM fingerprinting
#   - Cisco / SentinelOne / FuzzingLabs Ollama studies
#   - UpGuard Streamlit / ComfyUI exposure reports
# ---------------------------------------------------------------------------

AGENT_QUERIES: dict[str, str] = {
    # ── MCP (Model Context Protocol) ─────────────────────────────────────
    "mcp_protocol":        '"Model Context Protocol"',
    "mcp_sse":             'http.html:"mcp" content-type:"text/event-stream"',
    "mcp_sse_path":        'http.html:"/mcp/sse"',
    "mcp_jsonrpc":         'http.html:"/mcp" "jsonrpc"',

    # ── Ollama ───────────────────────────────────────────────────────────
    "ollama":              'port:11434 "Ollama is running"',
    "ollama_product":      'product:"Ollama"',
    "ollama_nonstandard":  '"Ollama is running" -port:11434',

    # ── OpenAI-compatible (vLLM, LiteLLM, LocalAI) ──────────────────────
    "vllm":                'http.html:"/v1/models" port:8000',
    "litellm":             '"LiteLLM" port:4000',
    "litellm_dashboard":   'http.title:"LiteLLM"',
    "localai":             '"LocalAI" port:8080',
    "openai_chat":         'http.html:"/v1/chat/completions"',

    # ── LangServe / LangChain ────────────────────────────────────────────
    "langserve":           'http.html:"langserve" "playground"',
    "langchain":           'http.html:"/playground" "langchain"',

    # ── Agent gateways (OpenClaw / Clawdbot) ─────────────────────────────
    "openclaw":            'http.title:"Clawdbot Control"',
    "openclaw_port":       'port:18789 "clawdbot"',
    "openclaw_noauth":     'port:18789 "auth_mode" "none"',

    # ── Chat UIs (Open WebUI, LibreChat) ─────────────────────────────────
    "open_webui":          'http.title:"Open WebUI"',
    "librechat":           'http.title:"LibreChat"',

    # ── Text generation (oobabooga) ──────────────────────────────────────
    "textgen_webui":       'http.title:"Text generation web UI" port:7860',

    # ── Gradio apps ──────────────────────────────────────────────────────
    "gradio":              'http.title:"Gradio"',
    "gradio_footer":       'http.html:"Built with Gradio"',
    "gradio_favicon":      'http.favicon.hash:945408572',

    # ── Streamlit apps ───────────────────────────────────────────────────
    "streamlit":           'http.title:"Streamlit"',
    "streamlit_favicon":   'http.favicon.hash:-335242539',

    # ── Image generation (ComfyUI, AUTOMATIC1111) ────────────────────────
    "comfyui":             'http.title:"ComfyUI"',
    "comfyui_port":        '"comfyui" port:8188',
    "stable_diffusion":    'http.title:"Stable Diffusion"',
    "sd_webui":            'http.html:"stable-diffusion-webui" port:7860',

    # ── Broad inference servers ──────────────────────────────────────────
    "huggingface_tgi":     'http.html:"huggingface" http.html:"model"',
    "api_generate":        'http.html:"/api/generate"',
    "api_tags":            'http.html:"/api/tags"',
}

# Human-readable descriptions for the UI (query-presets endpoint).
QUERY_DESCRIPTIONS: dict[str, str] = {
    "mcp_protocol":      "MCP servers (direct protocol match)",
    "mcp_sse":           "MCP Server-Sent Events transport",
    "mcp_sse_path":      "MCP /mcp/sse endpoint in HTML",
    "mcp_jsonrpc":       "MCP JSON-RPC references",
    "ollama":            "Ollama on default port 11434",
    "ollama_product":    "Ollama (Shodan product fingerprint)",
    "ollama_nonstandard": "Ollama on non-standard ports",
    "vllm":              "vLLM /v1/models on port 8000",
    "litellm":           "LiteLLM proxy on port 4000",
    "litellm_dashboard": "LiteLLM admin dashboard",
    "localai":           "LocalAI on port 8080",
    "openai_chat":       "OpenAI-compatible /v1/chat/completions",
    "langserve":         "LangServe with playground exposed",
    "langchain":         "LangChain /playground endpoints",
    "openclaw":          "Clawdbot/OpenClaw control dashboard",
    "openclaw_port":     "Clawdbot on default port 18789",
    "openclaw_noauth":   "OpenClaw with auth_mode: none",
    "open_webui":        "Open WebUI (Ollama frontend)",
    "librechat":         "LibreChat (multi-provider chat UI)",
    "textgen_webui":     "text-generation-webui (oobabooga)",
    "gradio":            "Gradio apps (title match)",
    "gradio_footer":     "Gradio apps (footer watermark)",
    "gradio_favicon":    "Gradio apps (favicon fingerprint)",
    "streamlit":         "Streamlit apps (title match)",
    "streamlit_favicon": "Streamlit apps (favicon fingerprint)",
    "comfyui":           "ComfyUI image generation",
    "comfyui_port":      "ComfyUI on default port 8188",
    "stable_diffusion":  "Stable Diffusion WebUI",
    "sd_webui":          "AUTOMATIC1111 SD WebUI on port 7860",
    "huggingface_tgi":   "HuggingFace TGI deployments",
    "api_generate":      "Ollama-style /api/generate endpoints",
    "api_tags":          "Ollama-style /api/tags model listing",
}


class ShodanAdapter(SourceAdapter):
    """Adapter that queries Shodan and normalizes results to AgentEndpoints.

    Parameters
    ----------
    api_key:
        Shodan API key.  Falls back to ``settings.SHODAN_API_KEY`` when not
        provided.
    """

    def __init__(self, api_key: str | None = None) -> None:
        self._api_key = api_key or settings.SHODAN_API_KEY
        if not self._api_key:
            raise ValueError(
                "Shodan API key is required. Set SHODAN_API_KEY in .env or "
                "pass api_key= to ShodanAdapter()."
            )
        self._client = shodan.Shodan(self._api_key)

    # -- SourceAdapter interface ---------------------------------------------

    @property
    def source_name(self) -> str:  # noqa: D401
        return "shodan"

    async def search(self, query: str, max_results: int = 100) -> AsyncIterator[dict]:
        """Query Shodan and yield raw result dicts.

        The SDK is synchronous so each page request is wrapped in
        ``asyncio.to_thread`` to avoid blocking the event loop.

        Parameters
        ----------
        query:
            Shodan search query string.
        max_results:
            Approximate upper bound -- may return slightly more due to page
            granularity (100 results per page).
        """
        page = 1
        yielded = 0

        while yielded < max_results:
            try:
                results = await asyncio.to_thread(
                    self._client.search, query, page=page
                )
            except shodan.APIError as exc:
                logger.error("Shodan API error on page %d: %s", page, exc)
                break
            except Exception:
                logger.exception("Unexpected error querying Shodan page %d", page)
                break

            matches = results.get("matches", [])
            if not matches:
                break

            for match in matches:
                if yielded >= max_results:
                    break
                yield match
                yielded += 1

            page += 1
            # Respect Shodan rate limit (1 req/s for basic plan)
            await asyncio.sleep(1.0)

        logger.info("Shodan search yielded %d results for query: %s", yielded, query)

    def normalize(self, raw: dict) -> dict:
        """Map a Shodan result dict to an AgentEndpoint-compatible dict.

        Shodan result structure (abbreviated)::

            {
                "ip_str": "104.21.32.50",
                "port": 8080,
                "hostnames": ["agent.example.com"],
                "data": "HTTP/1.1 200 OK\\r\\n...",
                "http": {
                    "headers": {...},
                    "html": "...",
                    "status": 200,
                },
                "location": {
                    "country_name": "United States",
                    "country_code": "US",
                    "region_code": "VA",
                    "city": "Ashburn",
                    "latitude": 39.0438,
                    "longitude": -77.4874,
                },
                "asn": "AS14618",
                "org": "Amazon.com, Inc.",
                "ssl": {...},
                ...
            }
        """
        ip = raw.get("ip_str", "")
        port = raw.get("port", 0)
        hostnames = raw.get("hostnames", [])
        hostname = hostnames[0] if hostnames else ""
        banner = raw.get("data", "")

        # Build URL
        scheme = "https" if raw.get("ssl") else "http"
        url = f"{scheme}://{hostname or ip}:{port}"

        # Geo
        loc = raw.get("location", {})
        geo = {
            "country": loc.get("country_name", ""),
            "country_code": loc.get("country_code", ""),
            "region": loc.get("region_code", ""),
            "city": loc.get("city", ""),
            "lat": loc.get("latitude", 0.0) or 0.0,
            "lon": loc.get("longitude", 0.0) or 0.0,
            "asn": raw.get("asn", ""),
            "org": raw.get("org", ""),
        }

        # Server info
        http_info = raw.get("http", {})
        headers = http_info.get("headers", {}) if http_info else {}
        # Normalise header keys to title-case for consistency
        if isinstance(headers, dict):
            headers = {k: v for k, v in headers.items()}
        server_banner = ""
        if isinstance(headers, dict):
            server_banner = headers.get("Server", headers.get("server", ""))
        if not server_banner:
            # Try to extract from raw banner
            server_match = re.search(r"Server:\s*(.+?)(?:\r?\n|$)", banner)
            if server_match:
                server_banner = server_match.group(1).strip()

        server = {
            "banner": server_banner or (banner[:200] if banner else ""),
            "headers": headers if isinstance(headers, dict) else {},
            "tls": bool(raw.get("ssl")),
            "cors_open": False,
        }

        # Detect CORS from headers
        if isinstance(headers, dict):
            acao = headers.get("Access-Control-Allow-Origin",
                               headers.get("access-control-allow-origin", ""))
            if acao == "*":
                server["cors_open"] = True

        # Detect protocol from banner / response content
        protocol = self._detect_protocol(banner, http_info)

        # Source record
        now = datetime.now(timezone.utc).isoformat()
        source_record = {
            "source": "shodan",
            "discovered_at": now,
            "raw_data": self._sanitize_for_mongo(raw),
        }

        return {
            "ip": ip,
            "port": port,
            "hostname": hostname,
            "url": url,
            "protocol": protocol,
            "auth_status": "unknown",
            "geo": geo,
            "server": server,
            "sources": [source_record],
        }

    # -- Helpers -------------------------------------------------------------

    @staticmethod
    def _sanitize_for_mongo(obj: Any) -> Any:
        """Recursively sanitize a dict/list so all integers fit MongoDB's 8-byte limit."""
        max_int = (2**63) - 1
        min_int = -(2**63)
        if isinstance(obj, dict):
            return {k: ShodanAdapter._sanitize_for_mongo(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [ShodanAdapter._sanitize_for_mongo(v) for v in obj]
        if isinstance(obj, int) and not isinstance(obj, bool):
            if obj > max_int or obj < min_int:
                return str(obj)
        return obj

    @staticmethod
    def _detect_protocol(banner: str, http_info: dict | None) -> str:
        """Infer the agent/service type from Shodan banner and HTTP data.

        Returns one of the ``ProtocolType`` literals.  Detection is ordered
        from most-specific to least-specific to avoid false positives.
        """
        combined = banner.lower()
        title = ""
        if http_info:
            html = (http_info.get("html") or "").lower()
            title = (http_info.get("title") or "").lower()
            combined = combined + " " + html + " " + title

        # ── Exact product matches (highest confidence) ───────────────
        if "ollama is running" in combined or "ollama" in title:
            return "ollama"

        if "clawdbot" in combined or "openclaw" in combined:
            return "openclaw"

        if "comfyui" in combined or "comfyui" in title:
            return "comfyui"

        if "stable diffusion" in title or "stable-diffusion-webui" in combined:
            return "stable_diffusion"

        if "text generation web ui" in title or "text-generation-webui" in combined:
            return "textgen_webui"

        if "open webui" in title:
            return "open_webui"

        if "librechat" in title:
            return "librechat"

        # ── Protocol-level detection ─────────────────────────────────
        # MCP -- JSON-RPC + capabilities or /mcp path
        if ("jsonrpc" in combined and "capabilities" in combined) or \
           "model context protocol" in combined or \
           "/mcp/sse" in combined or "/mcp" in combined:
            return "mcp"

        # OpenAI-compatible (vLLM, LiteLLM, LocalAI)
        if "/v1/models" in combined or "/v1/chat/completions" in combined:
            return "openai_compat"

        # LangServe / LangChain
        if "langserve" in combined or ("langchain" in combined and "/playground" in combined):
            return "langserve"

        # AutoGen
        if "autogen" in combined:
            return "autogen"

        # ── Framework-level detection ────────────────────────────────
        if "built with gradio" in combined or "gradio" in title:
            return "gradio"

        if "streamlit" in title or "streamlit" in combined:
            return "streamlit"

        if "huggingface" in combined or "hugging face" in combined:
            return "huggingface"

        # Ollama API endpoints without the banner string
        if "/api/generate" in combined or "/api/tags" in combined:
            return "ollama"

        return "unknown"

    @classmethod
    def get_agent_queries(cls) -> dict[str, str]:
        """Return the predefined Shodan search queries for agent discovery."""
        return dict(AGENT_QUERIES)
