"""Pydantic models for the ``scans`` MongoDB collection.

Each document tracks a scan job -- both active scanning and 3P ingestion runs.
"""

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field


# ── Nested models ────────────────────────────────────────────────


class ScanConfig(BaseModel):
    """Configuration for a scan job.

    For active scans: target CIDR, protocols, templates, ports, rate limit.
    For ingestion scans: source name, query, max results.
    """

    # Active scan fields
    target: str = ""
    range_id: str | None = None
    protocols: list[str] = Field(default_factory=list)
    templates: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)
    rate_limit: int = 1000
    timeout_ms: int = 5000

    # Ingestion scan fields
    source: str | None = None
    query: str | None = None
    max_results: int | None = None


class ScanProgress(BaseModel):
    """Live progress tracking for a running scan."""

    total_hosts: int = 0
    scanned: int = 0
    alive: int = 0
    agents_found: int = 0
    percent_complete: float = Field(default=0.0, ge=0.0, le=100.0)
    current_ip: str = ""
    started_at: datetime | None = None
    estimated_completion: datetime | None = None


class ResultsSummary(BaseModel):
    """Post-scan summary statistics."""

    total_endpoints: int = 0
    by_protocol: dict[str, int] = Field(default_factory=dict)
    by_risk: dict[str, int] = Field(default_factory=dict)
    no_auth_count: int = 0


# ── Main document model ─────────────────────────────────────────

ScanType = Literal["active", "ingestion"]
ScanStatus = Literal["queued", "running", "completed", "failed", "cancelled"]


class Scan(BaseModel):
    """Full scan job document (MongoDB doc)."""

    id: str = Field(default="", alias="_id")

    name: str = ""
    type: ScanType = "active"
    status: ScanStatus = "queued"

    config: ScanConfig = Field(default_factory=ScanConfig)
    progress: ScanProgress = Field(default_factory=ScanProgress)
    results_summary: ResultsSummary = Field(default_factory=ResultsSummary)

    endpoint_ids: list[str] = Field(default_factory=list)

    created_by: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = {"populate_by_name": True}


# ── Create DTO ───────────────────────────────────────────────────


class ScanCreate(BaseModel):
    """Fields required to create a new scan job."""

    name: str
    type: ScanType = "active"
    config: ScanConfig
    created_by: str = ""
