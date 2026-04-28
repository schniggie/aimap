"""Re-export all Pydantic models for convenient importing."""

from app.models.endpoint import (
    AgentEndpoint,
    AgentEndpointCreate,
    AgentEndpointUpdate,
    AuthStatus,
    GeoInfo,
    ProtocolType,
    ServerInfo,
    SourceRecord,
    ToolInfo,
    ToolRisk,
)
from app.models.analysis import (
    AgentAnalysis,
    AttackEdge,
    AttackGraph,
    AttackNode,
    ExploitationStep,
    Finding,
    Fingerprint,
    ScanRecord,
    TestingInfo,
    TestResult,
    ToolDetail,
)
from app.models.scan import (
    ResultsSummary,
    Scan,
    ScanConfig,
    ScanCreate,
    ScanProgress,
    ScanStatus,
    ScanType,
)
from app.models.range import (
    MonitoredRange,
    MonitoringConfig,
    RangeCreate,
    RangeStats,
    Trend,
)

__all__ = [
    # endpoint
    "AgentEndpoint",
    "AgentEndpointCreate",
    "AgentEndpointUpdate",
    "AuthStatus",
    "GeoInfo",
    "ProtocolType",
    "ServerInfo",
    "SourceRecord",
    "ToolInfo",
    "ToolRisk",
    # analysis
    "AgentAnalysis",
    "AttackEdge",
    "AttackGraph",
    "AttackNode",
    "ExploitationStep",
    "Finding",
    "Fingerprint",
    "ScanRecord",
    "TestingInfo",
    "TestResult",
    "ToolDetail",
    # scan
    "ResultsSummary",
    "Scan",
    "ScanConfig",
    "ScanCreate",
    "ScanProgress",
    "ScanStatus",
    "ScanType",
    # range
    "MonitoredRange",
    "MonitoringConfig",
    "RangeCreate",
    "RangeStats",
    "Trend",
]
