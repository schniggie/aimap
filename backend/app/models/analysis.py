"""Pydantic models for the ``analyses`` MongoDB collection.

Each document is a deep-dive record linked 1:1 from an endpoint.
Contains fingerprint data, scan records, and exploitation test results.
"""

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field


# ── Nested models: Fingerprint ───────────────────────────────────


class ToolDetail(BaseModel):
    """Extended tool information from fingerprinting."""

    name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)
    risk: Literal["critical", "high", "medium", "low", "info"] = "info"
    risk_reason: str = ""
    injectable: bool = False
    tested: bool = False
    injection_vector: str = ""


class Fingerprint(BaseModel):
    """Protocol-level fingerprint of an agent endpoint."""

    protocol_version: str = ""
    capabilities: list[str] = Field(default_factory=list)
    tool_details: list[ToolDetail] = Field(default_factory=list)
    system_prompt_full: str = ""
    model_detected: str = ""
    model_detection_method: str = ""
    permission_model: str = "none"
    rate_limiting: bool = False
    input_validation: str = "none"


# ── Nested models: Scans ────────────────────────────────────────


class Finding(BaseModel):
    """A single finding from an active scan."""

    template: str = ""
    severity: Literal["critical", "high", "medium", "low", "info"] = "info"
    title: str = ""
    detail: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)


class ScanRecord(BaseModel):
    """Record of an individual scan run against this endpoint."""

    scan_id: str = ""
    scan_type: str = ""  # e.g. "nuclei"
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    status: Literal["pending", "running", "completed", "failed"] = "pending"
    templates_run: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    raw_output: str = ""


# ── Nested models: Testing / Exploitation ────────────────────────


class TestResult(BaseModel):
    """Result of a single exploitation test."""

    test_id: str = ""
    category: str = ""  # e.g. "prompt_injection", "tool_injection"
    technique: str = ""  # e.g. "system_prompt_extraction", "chained_tool_abuse"
    payload: str = ""
    response: str = ""
    success: bool = False
    severity: Literal["critical", "high", "medium", "low", "info"] = "info"
    chain: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ExploitationStep(BaseModel):
    """A single step in the exploitation log."""

    step: int = 0
    reasoning: str = ""
    action: str = ""
    result: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AttackNode(BaseModel):
    """A node in the attack graph."""

    id: str
    type: str = ""  # e.g. "entry_point", "technique", "tool", "impact"
    label: str = ""


class AttackEdge(BaseModel):
    """An edge in the attack graph."""

    from_node: str = Field(alias="from", default="")
    to_node: str = Field(alias="to", default="")

    model_config = {"populate_by_name": True}


class AttackGraph(BaseModel):
    """Directed acyclic graph representing attack chains."""

    nodes: list[AttackNode] = Field(default_factory=list)
    edges: list[AttackEdge] = Field(default_factory=list)


class TestingInfo(BaseModel):
    """Aggregated exploitation / red-team testing data."""

    status: Literal["pending", "running", "completed", "failed", "not_tested"] = "not_tested"
    last_tested_at: datetime | None = None
    attack_surface: list[str] = Field(default_factory=list)
    attack_graph: AttackGraph = Field(default_factory=AttackGraph)
    test_results: list[TestResult] = Field(default_factory=list)
    exploitation_log: list[ExploitationStep] = Field(default_factory=list)


# ── Main document model ─────────────────────────────────────────


class AgentAnalysis(BaseModel):
    """Full analysis record for a single agent endpoint (MongoDB doc)."""

    id: str = Field(default="", alias="_id")
    endpoint_id: str = ""

    fingerprint: Fingerprint = Field(default_factory=Fingerprint)
    active_scans: list[ScanRecord] = Field(default_factory=list)
    testing: TestingInfo = Field(default_factory=TestingInfo)

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    analyzed_by: str = ""
    tags: list[str] = Field(default_factory=list)

    model_config = {"populate_by_name": True}
