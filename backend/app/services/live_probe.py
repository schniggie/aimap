"""Live HTTP probing for AI service endpoints.

During enrichment, we can make lightweight HTTP requests to well-known
API paths to discover what's actually running and what's exposed.

Supported services:
- **Ollama** — /api/tags, /api/version, /api/ps, /api/show
- **OpenAI-compatible** — /v1/models
- **LiteLLM** — /models, /health
- **vLLM** — /v1/models, /version
- **ComfyUI** — /system_stats, /object_info
- **Open WebUI** — /api/config
- **Gradio** — /info, /config
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# Timeout for live probes — keep short to avoid blocking enrichment
PROBE_TIMEOUT = 8.0


async def probe_endpoint(doc: dict) -> dict:
    """Probe a discovered endpoint's well-known API paths.

    Dispatches to protocol-specific probing based on the endpoint's
    ``protocol`` field (or tries multiple if ``unknown``).

    Returns a dict of fields to ``$set`` on the endpoint document.
    """
    protocol = doc.get("protocol", "unknown")
    ip = doc.get("ip", "")
    port = doc.get("port", 80)
    url = doc.get("url", "")

    if not url:
        tls = doc.get("server", {}).get("tls", False)
        scheme = "https" if tls else "http"
        url = f"{scheme}://{ip}:{port}"

    updates: dict[str, Any] = {}

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(PROBE_TIMEOUT),
        follow_redirects=True,
        verify=False,
    ) as client:
        # Route to protocol-specific probe
        if protocol == "ollama":
            updates = await _probe_ollama(client, url, doc)
        elif protocol in ("openai_compat", "vllm", "litellm"):
            updates = await _probe_openai_compat(client, url, doc)
        elif protocol == "comfyui":
            updates = await _probe_comfyui(client, url, doc)
        elif protocol == "gradio":
            updates = await _probe_gradio(client, url, doc)
        elif protocol == "open_webui":
            updates = await _probe_open_webui(client, url, doc)
        elif protocol == "unknown":
            # Try multiple probes to identify the service
            updates = await _probe_unknown(client, url, doc)

    return updates


# ---------------------------------------------------------------------------
# Ollama
# ---------------------------------------------------------------------------

_OLLAMA_DANGEROUS_MODELS = {
    "llama", "codellama", "mistral", "mixtral", "deepseek",
    "phi", "qwen", "gemma", "starcoder", "wizard",
}


async def _probe_ollama(
    client: httpx.AsyncClient, base_url: str, doc: dict
) -> dict:
    """Probe Ollama API endpoints.

    Standard Ollama endpoints:
    - GET  /              → "Ollama is running"
    - GET  /api/tags      → list of loaded models
    - GET  /api/version   → version string
    - GET  /api/ps        → currently running models + memory usage
    - POST /api/show      → model details (requires model name)
    """
    updates: dict[str, Any] = {}
    risk_factors: list[str] = list(doc.get("risk_factors", []))
    tags: list[str] = list(doc.get("tags", []))

    # -- GET / (confirm Ollama) --
    root_resp = await _safe_get(client, base_url)
    if root_resp and "ollama is running" in root_resp.get("body", "").lower():
        if "ollama_confirmed" not in tags:
            tags.append("ollama_confirmed")

    # -- GET /api/version --
    version_resp = await _safe_get(client, f"{base_url}/api/version")
    if version_resp and version_resp.get("ok"):
        try:
            version_data = json.loads(version_resp["body"])
            version = version_data.get("version", "")
            if version:
                updates["framework"] = f"ollama/{version}"
                if "ollama_version" not in tags:
                    tags.append(f"ollama_v{version}")
        except (json.JSONDecodeError, ValueError):
            pass

    # -- GET /api/tags (model list) --
    tags_resp = await _safe_get(client, f"{base_url}/api/tags")
    if tags_resp and tags_resp.get("ok"):
        try:
            tags_data = json.loads(tags_resp["body"])
            models = tags_data.get("models", [])
            if models:
                model_names = [m.get("name", "") for m in models if m.get("name")]
                model_sizes = []
                for m in models:
                    size_bytes = m.get("size", 0)
                    if size_bytes:
                        size_gb = size_bytes / (1024 ** 3)
                        model_sizes.append(f"{m.get('name', '?')}({size_gb:.1f}GB)")

                # Set the primary model to the first one
                if model_names and not doc.get("model"):
                    updates["model"] = model_names[0]

                # Build tool-like entries for each model (models are the "tools" of Ollama)
                tools = []
                for m in models:
                    name = m.get("name", "")
                    size = m.get("size", 0)
                    size_gb = size / (1024 ** 3) if size else 0
                    modified = m.get("modified_at", "")
                    digest = m.get("digest", "")[:12]
                    family = m.get("details", {}).get("family", "")
                    param_size = m.get("details", {}).get("parameter_size", "")
                    quant = m.get("details", {}).get("quantization_level", "")

                    desc_parts = []
                    if param_size:
                        desc_parts.append(param_size)
                    if family:
                        desc_parts.append(f"family: {family}")
                    if quant:
                        desc_parts.append(f"quant: {quant}")
                    if size_gb > 0:
                        desc_parts.append(f"{size_gb:.1f}GB")

                    # Determine risk: large unrestricted models are higher risk
                    risk = "medium"
                    risk_reason = "Model accessible without auth"
                    if any(d in name.lower() for d in ("uncensored", "abliterated")):
                        risk = "critical"
                        risk_reason = "Uncensored/abliterated model — no safety guardrails"
                    elif size_gb > 20:
                        risk = "high"
                        risk_reason = f"Large model ({size_gb:.0f}GB) exposed without auth"
                    elif doc.get("auth_status") == "none":
                        risk = "high"
                        risk_reason = "Model accessible without authentication"

                    tools.append({
                        "name": name,
                        "description": ", ".join(desc_parts) if desc_parts else f"Ollama model {digest}",
                        "parameters": {
                            "size_bytes": size,
                            "digest": m.get("digest", ""),
                            "family": family,
                            "parameter_size": param_size,
                            "quantization": quant,
                            "modified_at": modified,
                        },
                        "risk": risk,
                        "risk_reason": risk_reason,
                    })

                # Only update tools if we found more models than current tools
                current_tools = doc.get("tools", [])
                if len(tools) > len(current_tools):
                    updates["tools"] = tools
                    updates["tool_count"] = len(tools)

                if len(model_names) > 0:
                    if "models_exposed" not in risk_factors:
                        risk_factors.append("models_exposed")
                    # Tag with model count
                    count_tag = f"models:{len(model_names)}"
                    if count_tag not in tags:
                        tags.append(count_tag)

                # Check for dangerous model types
                for name in model_names:
                    name_lower = name.lower()
                    if "uncensored" in name_lower or "abliterated" in name_lower:
                        if "uncensored_model" not in risk_factors:
                            risk_factors.append("uncensored_model")
                        if "uncensored" not in tags:
                            tags.append("uncensored")

        except (json.JSONDecodeError, ValueError):
            pass

    # -- GET /api/ps (running models / resource usage) --
    ps_resp = await _safe_get(client, f"{base_url}/api/ps")
    if ps_resp and ps_resp.get("ok"):
        try:
            ps_data = json.loads(ps_resp["body"])
            running = ps_data.get("models", [])
            if running:
                running_names = [m.get("name", "") for m in running]
                if "actively_serving" not in tags:
                    tags.append("actively_serving")
                # Log VRAM usage
                for m in running:
                    vram = m.get("size_vram", 0)
                    if vram:
                        vram_gb = vram / (1024 ** 3)
                        logger.info(
                            "Ollama %s: model %s using %.1fGB VRAM",
                            base_url, m.get("name"), vram_gb,
                        )
        except (json.JSONDecodeError, ValueError):
            pass

    # Auth: if we got model list, there's no auth
    if tags_resp and tags_resp.get("ok"):
        if doc.get("auth_status", "unknown") in ("unknown",):
            updates["auth_status"] = "none"
            if "no_auth" not in risk_factors:
                risk_factors.append("no_auth")

    if risk_factors != list(doc.get("risk_factors", [])):
        updates["risk_factors"] = risk_factors
    if tags != list(doc.get("tags", [])):
        updates["tags"] = tags

    return updates


# ---------------------------------------------------------------------------
# OpenAI-compatible (vLLM, LiteLLM, etc.)
# ---------------------------------------------------------------------------

async def _probe_openai_compat(
    client: httpx.AsyncClient, base_url: str, doc: dict
) -> dict:
    """Probe OpenAI-compatible endpoints: /v1/models, /health."""
    updates: dict[str, Any] = {}
    risk_factors: list[str] = list(doc.get("risk_factors", []))
    tags: list[str] = list(doc.get("tags", []))

    # -- GET /v1/models --
    models_resp = await _safe_get(client, f"{base_url}/v1/models")
    if models_resp and models_resp.get("ok"):
        try:
            data = json.loads(models_resp["body"])
            model_list = data.get("data", [])
            if model_list:
                model_ids = [m.get("id", "") for m in model_list if m.get("id")]
                if model_ids and not doc.get("model"):
                    updates["model"] = model_ids[0]

                tools = []
                for m in model_list:
                    mid = m.get("id", "")
                    owned_by = m.get("owned_by", "")
                    tools.append({
                        "name": mid,
                        "description": f"Model served via OpenAI-compat API (owner: {owned_by})" if owned_by else "Model served via OpenAI-compat API",
                        "parameters": {k: v for k, v in m.items() if k != "id"},
                        "risk": "high" if doc.get("auth_status") == "none" else "medium",
                        "risk_reason": "Model API accessible" + (" without auth" if doc.get("auth_status") == "none" else ""),
                    })

                current_tools = doc.get("tools", [])
                if len(tools) > len(current_tools):
                    updates["tools"] = tools
                    updates["tool_count"] = len(tools)

                if "models_exposed" not in risk_factors:
                    risk_factors.append("models_exposed")

                count_tag = f"models:{len(model_ids)}"
                if count_tag not in tags:
                    tags.append(count_tag)

                # If we got models, no auth
                if doc.get("auth_status", "unknown") == "unknown":
                    updates["auth_status"] = "none"
                    if "no_auth" not in risk_factors:
                        risk_factors.append("no_auth")

        except (json.JSONDecodeError, ValueError):
            pass
    elif models_resp and models_resp.get("status") in (401, 403):
        if doc.get("auth_status", "unknown") == "unknown":
            updates["auth_status"] = "api_key"

    # -- GET /health (LiteLLM / vLLM) --
    health_resp = await _safe_get(client, f"{base_url}/health")
    if health_resp and health_resp.get("ok"):
        body = health_resp.get("body", "").lower()
        if "litellm" in body:
            if not doc.get("framework"):
                updates["framework"] = "litellm"
            updates.setdefault("protocol", doc.get("protocol", "litellm"))
        elif "vllm" in body or "version" in body:
            if not doc.get("framework"):
                updates["framework"] = "vllm"

    # -- GET /version (vLLM) --
    ver_resp = await _safe_get(client, f"{base_url}/version")
    if ver_resp and ver_resp.get("ok"):
        try:
            vdata = json.loads(ver_resp["body"])
            v = vdata.get("version", "")
            if v and not doc.get("framework"):
                updates["framework"] = f"vllm/{v}"
        except (json.JSONDecodeError, ValueError):
            pass

    if risk_factors != list(doc.get("risk_factors", [])):
        updates["risk_factors"] = risk_factors
    if tags != list(doc.get("tags", [])):
        updates["tags"] = tags

    return updates


# ---------------------------------------------------------------------------
# ComfyUI
# ---------------------------------------------------------------------------

async def _probe_comfyui(
    client: httpx.AsyncClient, base_url: str, doc: dict
) -> dict:
    """Probe ComfyUI: /system_stats, /object_info."""
    updates: dict[str, Any] = {}
    risk_factors: list[str] = list(doc.get("risk_factors", []))
    tags: list[str] = list(doc.get("tags", []))

    # -- GET /system_stats --
    stats_resp = await _safe_get(client, f"{base_url}/system_stats")
    if stats_resp and stats_resp.get("ok"):
        try:
            data = json.loads(stats_resp["body"])
            system = data.get("system", {})
            devices = data.get("devices", [])
            if system or devices:
                if "comfyui_confirmed" not in tags:
                    tags.append("comfyui_confirmed")
                # Extract GPU info
                for dev in devices:
                    name = dev.get("name", "")
                    vram = dev.get("vram_total", 0)
                    if name:
                        tags.append(f"gpu:{name}")
                if doc.get("auth_status", "unknown") == "unknown":
                    updates["auth_status"] = "none"
                    if "no_auth" not in risk_factors:
                        risk_factors.append("no_auth")
        except (json.JSONDecodeError, ValueError):
            pass

    # -- GET /object_info (lists all nodes/tools) --
    obj_resp = await _safe_get(client, f"{base_url}/object_info")
    if obj_resp and obj_resp.get("ok"):
        try:
            data = json.loads(obj_resp["body"])
            if isinstance(data, dict) and len(data) > 0:
                node_count = len(data)
                # Pick out notable nodes
                dangerous_nodes = [
                    k for k in data
                    if any(d in k.lower() for d in ("execute", "shell", "load", "save", "write"))
                ]
                tools = []
                for name in list(data.keys())[:50]:  # Cap at 50
                    node = data[name]
                    desc = node.get("description", "") if isinstance(node, dict) else ""
                    tools.append({
                        "name": name,
                        "description": desc or f"ComfyUI node",
                        "parameters": {},
                        "risk": "medium",
                        "risk_reason": "ComfyUI node exposed",
                    })

                current_tools = doc.get("tools", [])
                if len(tools) > len(current_tools):
                    updates["tools"] = tools
                    updates["tool_count"] = node_count

                count_tag = f"nodes:{node_count}"
                if count_tag not in tags:
                    tags.append(count_tag)

        except (json.JSONDecodeError, ValueError):
            pass

    if risk_factors != list(doc.get("risk_factors", [])):
        updates["risk_factors"] = risk_factors
    if tags != list(doc.get("tags", [])):
        updates["tags"] = tags

    return updates


# ---------------------------------------------------------------------------
# Gradio
# ---------------------------------------------------------------------------

async def _probe_gradio(
    client: httpx.AsyncClient, base_url: str, doc: dict
) -> dict:
    """Probe Gradio: /info, /config."""
    updates: dict[str, Any] = {}
    tags: list[str] = list(doc.get("tags", []))
    risk_factors: list[str] = list(doc.get("risk_factors", []))

    # -- GET /info --
    info_resp = await _safe_get(client, f"{base_url}/info")
    if info_resp and info_resp.get("ok"):
        try:
            data = json.loads(info_resp["body"])
            version = data.get("version", "")
            if version:
                updates["framework"] = f"gradio/{version}"
        except (json.JSONDecodeError, ValueError):
            pass

    # -- GET /config --
    config_resp = await _safe_get(client, f"{base_url}/config")
    if config_resp and config_resp.get("ok"):
        try:
            data = json.loads(config_resp["body"])
            if isinstance(data, dict):
                if "gradio_confirmed" not in tags:
                    tags.append("gradio_confirmed")
                # Check auth
                auth_required = data.get("auth_required", False)
                if not auth_required:
                    if doc.get("auth_status", "unknown") == "unknown":
                        updates["auth_status"] = "none"
                        if "no_auth" not in risk_factors:
                            risk_factors.append("no_auth")
                else:
                    if doc.get("auth_status", "unknown") == "unknown":
                        updates["auth_status"] = "basic"

                # Extract API endpoints as tools
                dependencies = data.get("dependencies", [])
                if dependencies:
                    tools = []
                    for dep in dependencies[:30]:
                        api_name = dep.get("api_name", "")
                        if not api_name:
                            continue
                        inputs = dep.get("inputs", [])
                        tools.append({
                            "name": api_name,
                            "description": f"Gradio API endpoint ({len(inputs)} inputs)",
                            "parameters": {"inputs": inputs},
                            "risk": "medium",
                            "risk_reason": "Gradio endpoint exposed",
                        })
                    current_tools = doc.get("tools", [])
                    if len(tools) > len(current_tools):
                        updates["tools"] = tools
                        updates["tool_count"] = len(tools)

        except (json.JSONDecodeError, ValueError):
            pass

    if risk_factors != list(doc.get("risk_factors", [])):
        updates["risk_factors"] = risk_factors
    if tags != list(doc.get("tags", [])):
        updates["tags"] = tags

    return updates


# ---------------------------------------------------------------------------
# Open WebUI
# ---------------------------------------------------------------------------

async def _probe_open_webui(
    client: httpx.AsyncClient, base_url: str, doc: dict
) -> dict:
    """Probe Open WebUI: /api/config."""
    updates: dict[str, Any] = {}
    tags: list[str] = list(doc.get("tags", []))

    config_resp = await _safe_get(client, f"{base_url}/api/config")
    if config_resp and config_resp.get("ok"):
        try:
            data = json.loads(config_resp["body"])
            if isinstance(data, dict):
                if "open_webui_confirmed" not in tags:
                    tags.append("open_webui_confirmed")
                version = data.get("version", "")
                if version and not doc.get("framework"):
                    updates["framework"] = f"open-webui/{version}"

                # Check if signup is enabled (a big exposure)
                features = data.get("features", {})
                if features.get("enable_signup", False):
                    if "signup_enabled" not in tags:
                        tags.append("signup_enabled")
                    risk_factors = list(doc.get("risk_factors", []))
                    if "signup_enabled" not in risk_factors:
                        risk_factors.append("signup_enabled")
                        updates["risk_factors"] = risk_factors

        except (json.JSONDecodeError, ValueError):
            pass

    if tags != list(doc.get("tags", [])):
        updates["tags"] = tags

    return updates


# ---------------------------------------------------------------------------
# Unknown protocol — try multiple probes
# ---------------------------------------------------------------------------

async def _probe_unknown(
    client: httpx.AsyncClient, base_url: str, doc: dict
) -> dict:
    """When protocol is unknown, try several well-known endpoints to identify the service."""
    updates: dict[str, Any] = {}

    # Try Ollama first (most common discovery)
    root_resp = await _safe_get(client, base_url)
    if root_resp and "ollama is running" in root_resp.get("body", "").lower():
        updates["protocol"] = "ollama"
        ollama_updates = await _probe_ollama(client, base_url, {**doc, "protocol": "ollama"})
        updates.update(ollama_updates)
        return updates

    # Try OpenAI-compat
    models_resp = await _safe_get(client, f"{base_url}/v1/models")
    if models_resp and models_resp.get("ok"):
        try:
            data = json.loads(models_resp.get("body", ""))
            if "data" in data:
                updates["protocol"] = "openai_compat"
                compat_updates = await _probe_openai_compat(
                    client, base_url, {**doc, "protocol": "openai_compat"}
                )
                updates.update(compat_updates)
                return updates
        except (json.JSONDecodeError, ValueError):
            pass

    # Try Gradio
    config_resp = await _safe_get(client, f"{base_url}/config")
    if config_resp and config_resp.get("ok"):
        body = config_resp.get("body", "")
        if '"dependencies"' in body or '"version"' in body:
            try:
                data = json.loads(body)
                if "dependencies" in data:
                    updates["protocol"] = "gradio"
                    gradio_updates = await _probe_gradio(
                        client, base_url, {**doc, "protocol": "gradio"}
                    )
                    updates.update(gradio_updates)
                    return updates
            except (json.JSONDecodeError, ValueError):
                pass

    # Try ComfyUI
    stats_resp = await _safe_get(client, f"{base_url}/system_stats")
    if stats_resp and stats_resp.get("ok"):
        try:
            data = json.loads(stats_resp.get("body", ""))
            if "system" in data or "devices" in data:
                updates["protocol"] = "comfyui"
                comfy_updates = await _probe_comfyui(
                    client, base_url, {**doc, "protocol": "comfyui"}
                )
                updates.update(comfy_updates)
                return updates
        except (json.JSONDecodeError, ValueError):
            pass

    return updates


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _safe_get(
    client: httpx.AsyncClient, url: str
) -> dict[str, Any] | None:
    """Make a GET request, returning None on any error."""
    try:
        resp = await client.get(url)
        return {
            "ok": 200 <= resp.status_code < 300,
            "status": resp.status_code,
            "body": resp.text[:10000],
            "headers": dict(resp.headers),
        }
    except (httpx.ConnectError, httpx.TimeoutException, httpx.RemoteProtocolError):
        return None
    except Exception:
        logger.debug("Probe failed for %s", url, exc_info=True)
        return None
