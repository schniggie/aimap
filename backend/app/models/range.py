"""Pydantic models for the ``ranges`` MongoDB collection.

Each document represents a monitored IP range with scheduling and stats.
"""

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field


# ── Nested models ────────────────────────────────────────────────


class MonitoringConfig(BaseModel):
    """Recurring scan scheduling configuration."""

    enabled: bool = False
    interval_hours: int = Field(default=24, ge=1)
    last_scan_id: str | None = None
    last_scanned_at: datetime | None = None
    next_scan_at: datetime | None = None


class Trend(BaseModel):
    """Endpoint count trend data."""

    endpoints_7d_ago: int = 0
    endpoints_30d_ago: int = 0
    direction: Literal["increasing", "decreasing", "stable"] = "stable"


class RangeStats(BaseModel):
    """Aggregated statistics for a monitored range."""

    total_endpoints: int = 0
    by_protocol: dict[str, int] = Field(default_factory=dict)
    by_risk: dict[str, int] = Field(default_factory=dict)
    no_auth_count: int = 0
    trend: Trend = Field(default_factory=Trend)


# ── Main document model ─────────────────────────────────────────


class MonitoredRange(BaseModel):
    """Full monitored IP range document (MongoDB doc)."""

    id: str = Field(default="", alias="_id")

    name: str = ""
    cidr: str = ""
    total_hosts: int = 0

    monitoring: MonitoringConfig = Field(default_factory=MonitoringConfig)
    stats: RangeStats = Field(default_factory=RangeStats)

    scan_ids: list[str] = Field(default_factory=list)

    created_by: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tags: list[str] = Field(default_factory=list)

    model_config = {"populate_by_name": True}


# ── Create DTO ───────────────────────────────────────────────────


class RangeCreate(BaseModel):
    """Fields required to create a new monitored range."""

    name: str
    cidr: str
    total_hosts: int = 0
    monitoring: MonitoringConfig = Field(default_factory=MonitoringConfig)
    created_by: str = ""
    tags: list[str] = Field(default_factory=list)
