"""Pydantic models for the ``endpoints`` MongoDB collection.

Each document represents a unique (ip, port, protocol) discovery record.
"""

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, field_validator


# ── Enums as Literal types ───────────────────────────────────────
from typing import Literal

ProtocolType = Literal[
    "mcp",
    "openai_compat",
    "langserve",
    "autogen",
    "ollama",
    "gradio",
    "streamlit",
    "comfyui",
    "stable_diffusion",
    "textgen_webui",
    "openclaw",
    "open_webui",
    "librechat",
    "huggingface",
    "unknown",
]
AuthStatus = Literal["none", "api_key", "api_key_weak", "oauth", "basic", "unknown"]
ToolRisk = Literal["critical", "high", "medium", "low", "info"]


# ── Nested models ────────────────────────────────────────────────


class ToolInfo(BaseModel):
    """A tool registered on an agent endpoint."""

    name: str
    description: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)
    risk: ToolRisk = "info"
    risk_reason: str = ""


class GeoInfo(BaseModel):
    """Geographic / network location information."""

    country: str = ""
    country_code: str = ""
    region: str = ""
    city: str = ""
    lat: float = 0.0
    lon: float = 0.0
    asn: str = ""
    org: str = ""


class ServerInfo(BaseModel):
    """HTTP server metadata."""

    banner: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    tls: bool = False
    cors_open: bool = False


class SourceRecord(BaseModel):
    """How / when this endpoint was discovered from a particular source."""

    source: str  # e.g. "shodan", "censys", "nuclei"
    scan_id: str | None = None
    template: str | None = None
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    raw_data: dict[str, Any] = Field(default_factory=dict)


# ── Main document model ─────────────────────────────────────────


class AgentEndpoint(BaseModel):
    """Full representation of a discovered agent endpoint (MongoDB doc)."""

    id: str = Field(default="", alias="_id")

    # Network identity
    ip: str
    port: int = Field(ge=1, le=65535)
    hostname: str = ""
    url: str = ""

    # Agent classification
    protocol: ProtocolType
    framework: str = ""
    model: str = ""
    auth_status: AuthStatus = "unknown"

    # Tools
    tools: list[ToolInfo] = Field(default_factory=list)
    tool_count: int = 0
    dangerous_combos: list[str] = Field(default_factory=list)

    # System prompt
    system_prompt: str = ""
    system_prompt_extracted: bool = False

    # Risk
    risk_score: float = Field(default=0.0, ge=0.0, le=10.0)
    risk_factors: list[str] = Field(default_factory=list)

    # Geo / server
    geo: GeoInfo = Field(default_factory=GeoInfo)
    server: ServerInfo = Field(default_factory=ServerInfo)

    # Provenance
    sources: list[SourceRecord] = Field(default_factory=list)
    range_id: str | None = None
    scan_ids: list[str] = Field(default_factory=list)
    analysis_id: str | None = None

    # Timestamps
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # User-defined labels
    tags: list[str] = Field(default_factory=list)

    model_config = {
        "populate_by_name": True,
        "json_schema_extra": {
            "example": {
                "ip": "104.21.32.50",
                "port": 8080,
                "protocol": "mcp",
                "auth_status": "none",
                "risk_score": 9.2,
            }
        },
    }

    @field_validator("risk_score")
    @classmethod
    def clamp_risk_score(cls, v: float) -> float:
        if v < 0.0 or v > 10.0:
            raise ValueError("risk_score must be between 0.0 and 10.0")
        return v


# ── Create / Update DTOs ─────────────────────────────────────────


class AgentEndpointCreate(BaseModel):
    """Fields required to insert a new endpoint."""

    ip: str
    port: int = Field(ge=1, le=65535)
    protocol: ProtocolType
    hostname: str = ""
    url: str = ""
    framework: str = ""
    model: str = ""
    auth_status: AuthStatus = "unknown"
    tools: list[ToolInfo] = Field(default_factory=list)
    tool_count: int = 0
    dangerous_combos: list[str] = Field(default_factory=list)
    system_prompt: str = ""
    system_prompt_extracted: bool = False
    risk_score: float = Field(default=0.0, ge=0.0, le=10.0)
    risk_factors: list[str] = Field(default_factory=list)
    geo: GeoInfo = Field(default_factory=GeoInfo)
    server: ServerInfo = Field(default_factory=ServerInfo)
    sources: list[SourceRecord] = Field(default_factory=list)
    range_id: str | None = None
    scan_ids: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    @field_validator("risk_score")
    @classmethod
    def clamp_risk_score(cls, v: float) -> float:
        if v < 0.0 or v > 10.0:
            raise ValueError("risk_score must be between 0.0 and 10.0")
        return v


class AgentEndpointUpdate(BaseModel):
    """Optional fields for partial updates."""

    hostname: str | None = None
    url: str | None = None
    framework: str | None = None
    model: str | None = None
    auth_status: AuthStatus | None = None
    tools: list[ToolInfo] | None = None
    tool_count: int | None = None
    dangerous_combos: list[str] | None = None
    system_prompt: str | None = None
    system_prompt_extracted: bool | None = None
    risk_score: float | None = Field(default=None, ge=0.0, le=10.0)
    risk_factors: list[str] | None = None
    geo: GeoInfo | None = None
    server: ServerInfo | None = None
    sources: list[SourceRecord] | None = None
    range_id: str | None = None
    scan_ids: list[str] | None = None
    analysis_id: str | None = None
    tags: list[str] | None = None
