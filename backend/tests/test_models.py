"""Tests for Pydantic models — instantiation, validation, and serialization."""

from datetime import datetime

import pytest
from pydantic import ValidationError

from app.models.endpoint import (
    AgentEndpoint,
    AgentEndpointCreate,
    AgentEndpointUpdate,
    GeoInfo,
    ServerInfo,
    SourceRecord,
    ToolInfo,
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
)
from app.models.range import (
    MonitoredRange,
    MonitoringConfig,
    RangeCreate,
    RangeStats,
    Trend,
)


# ═══════════════════════════════════════════════════════════════════
# AgentEndpoint
# ═══════════════════════════════════════════════════════════════════


class TestAgentEndpoint:
    """Tests for AgentEndpoint and its nested models."""

    def test_minimal_valid(self):
        ep = AgentEndpoint(ip="1.2.3.4", port=8080, protocol="mcp")
        assert ep.ip == "1.2.3.4"
        assert ep.port == 8080
        assert ep.protocol == "mcp"
        assert ep.auth_status == "unknown"
        assert ep.risk_score == 0.0

    def test_full_valid(self):
        ep = AgentEndpoint(
            _id="ep_001",
            ip="104.21.32.50",
            port=8080,
            hostname="agent.example.com",
            url="http://104.21.32.50:8080",
            protocol="mcp",
            framework="fastapi",
            model="claude-sonnet-4-5-20250514",
            auth_status="none",
            tools=[
                ToolInfo(
                    name="query_db",
                    description="Execute SQL queries",
                    risk="critical",
                    risk_reason="Raw SQL execution",
                )
            ],
            tool_count=1,
            dangerous_combos=["db_read + email"],
            system_prompt="You are a database assistant...",
            system_prompt_extracted=True,
            risk_score=9.2,
            risk_factors=["no_auth", "tool_injection"],
            geo=GeoInfo(
                country="US",
                country_code="US",
                region="Virginia",
                city="Ashburn",
                lat=39.0438,
                lon=-77.4874,
                asn="AS14618",
                org="Amazon AWS",
            ),
            server=ServerInfo(
                banner="uvicorn/0.29.0",
                headers={"Server": "uvicorn"},
                tls=False,
                cors_open=True,
            ),
            sources=[
                SourceRecord(source="shodan"),
                SourceRecord(source="nuclei", scan_id="scan_001", template="mcp-detect"),
            ],
            range_id="range_xyz",
            scan_ids=["scan_001"],
            analysis_id="an_001",
            tags=["aws", "critical"],
        )
        assert ep.id == "ep_001"
        assert ep.tools[0].name == "query_db"
        assert ep.geo.country_code == "US"
        assert ep.server.cors_open is True
        assert len(ep.sources) == 2

    def test_invalid_risk_score_too_high(self):
        with pytest.raises(ValidationError, match="risk_score"):
            AgentEndpoint(ip="1.2.3.4", port=80, protocol="mcp", risk_score=11.0)

    def test_invalid_risk_score_too_low(self):
        with pytest.raises(ValidationError, match="risk_score"):
            AgentEndpoint(ip="1.2.3.4", port=80, protocol="mcp", risk_score=-1.0)

    def test_invalid_protocol(self):
        with pytest.raises(ValidationError):
            AgentEndpoint(ip="1.2.3.4", port=80, protocol="grpc")

    def test_invalid_port_zero(self):
        with pytest.raises(ValidationError):
            AgentEndpoint(ip="1.2.3.4", port=0, protocol="mcp")

    def test_invalid_port_too_high(self):
        with pytest.raises(ValidationError):
            AgentEndpoint(ip="1.2.3.4", port=70000, protocol="mcp")

    def test_invalid_auth_status(self):
        with pytest.raises(ValidationError):
            AgentEndpoint(ip="1.2.3.4", port=80, protocol="mcp", auth_status="magic")

    def test_serialization_to_dict(self):
        ep = AgentEndpoint(
            ip="10.0.0.1",
            port=443,
            protocol="openai_compat",
            risk_score=5.0,
            tags=["test"],
        )
        d = ep.model_dump(by_alias=True)
        assert d["ip"] == "10.0.0.1"
        assert d["_id"] == ""
        assert d["protocol"] == "openai_compat"
        assert isinstance(d["created_at"], datetime)

    def test_tool_info_risk_enum(self):
        with pytest.raises(ValidationError):
            ToolInfo(name="x", risk="extreme")

    def test_endpoint_create(self):
        c = AgentEndpointCreate(ip="1.2.3.4", port=80, protocol="langserve")
        assert c.ip == "1.2.3.4"
        assert c.auth_status == "unknown"

    def test_endpoint_create_invalid_risk(self):
        with pytest.raises(ValidationError):
            AgentEndpointCreate(ip="1.2.3.4", port=80, protocol="mcp", risk_score=99.0)

    def test_endpoint_update_partial(self):
        u = AgentEndpointUpdate(risk_score=7.5, tags=["updated"])
        assert u.risk_score == 7.5
        assert u.hostname is None


# ═══════════════════════════════════════════════════════════════════
# AgentAnalysis
# ═══════════════════════════════════════════════════════════════════


class TestAgentAnalysis:
    """Tests for AgentAnalysis and its nested models."""

    def test_minimal_valid(self):
        a = AgentAnalysis(endpoint_id="ep_001")
        assert a.endpoint_id == "ep_001"
        assert a.testing.status == "not_tested"

    def test_full_valid(self):
        a = AgentAnalysis(
            _id="an_001",
            endpoint_id="ep_001",
            fingerprint=Fingerprint(
                protocol_version="MCP/1.0",
                capabilities=["tools", "prompts"],
                tool_details=[
                    ToolDetail(
                        name="query_db",
                        description="Execute SQL",
                        risk="critical",
                        injectable=True,
                        tested=True,
                        injection_vector="Parameter value passed to SQL",
                    )
                ],
                system_prompt_full="You are a database assistant...",
                model_detected="claude-sonnet-4-5-20250514",
                model_detection_method="response_pattern",
            ),
            active_scans=[
                ScanRecord(
                    scan_id="scan_001",
                    scan_type="nuclei",
                    status="completed",
                    templates_run=["mcp-server-detect"],
                    findings=[
                        Finding(
                            template="mcp-tool-enum",
                            severity="high",
                            title="Unauthenticated tool listing",
                        )
                    ],
                )
            ],
            testing=TestingInfo(
                status="completed",
                attack_surface=["prompt_injection", "tool_injection"],
                attack_graph=AttackGraph(
                    nodes=[
                        AttackNode(id="entry", type="entry_point", label="Unauth MCP"),
                        AttackNode(id="exfil", type="impact", label="Data exfil"),
                    ],
                    edges=[
                        AttackEdge(**{"from": "entry", "to": "exfil"}),
                    ],
                ),
                test_results=[
                    TestResult(
                        test_id="test_001",
                        category="prompt_injection",
                        technique="system_prompt_extraction",
                        payload="Ignore previous instructions...",
                        response="You are a database assistant...",
                        success=True,
                        severity="high",
                    )
                ],
                exploitation_log=[
                    ExploitationStep(
                        step=1,
                        reasoning="Target has query_db + send_email",
                        action="Attempting system prompt extraction",
                        result="System prompt extracted",
                    )
                ],
            ),
            analyzed_by="user_xyz",
            tags=["critical"],
        )
        assert a.id == "an_001"
        assert a.fingerprint.protocol_version == "MCP/1.0"
        assert len(a.fingerprint.tool_details) == 1
        assert a.fingerprint.tool_details[0].injectable is True
        assert len(a.active_scans) == 1
        assert a.active_scans[0].findings[0].severity == "high"
        assert a.testing.status == "completed"
        assert len(a.testing.attack_graph.nodes) == 2
        assert len(a.testing.attack_graph.edges) == 1
        assert a.testing.test_results[0].success is True
        assert a.testing.exploitation_log[0].step == 1

    def test_attack_edge_alias(self):
        edge = AttackEdge(**{"from": "a", "to": "b"})
        assert edge.from_node == "a"
        assert edge.to_node == "b"
        d = edge.model_dump(by_alias=True)
        assert d["from"] == "a"
        assert d["to"] == "b"

    def test_invalid_finding_severity(self):
        with pytest.raises(ValidationError):
            Finding(severity="extreme")

    def test_invalid_testing_status(self):
        with pytest.raises(ValidationError):
            TestingInfo(status="invalid_status")

    def test_serialization_to_dict(self):
        a = AgentAnalysis(endpoint_id="ep_001")
        d = a.model_dump(by_alias=True)
        assert d["endpoint_id"] == "ep_001"
        assert d["_id"] == ""
        assert d["testing"]["status"] == "not_tested"
        assert isinstance(d["testing"]["attack_graph"]["nodes"], list)


# ═══════════════════════════════════════════════════════════════════
# Scan
# ═══════════════════════════════════════════════════════════════════


class TestScan:
    """Tests for Scan and its nested models."""

    def test_minimal_valid(self):
        s = Scan()
        assert s.status == "queued"
        assert s.type == "active"

    def test_active_scan_full(self):
        s = Scan(
            _id="scan_001",
            name="AWS us-east-1 sweep",
            type="active",
            status="running",
            config=ScanConfig(
                target="104.21.0.0/16",
                range_id="range_xyz",
                protocols=["mcp", "openai_compat"],
                templates=["mcp-server-detect"],
                ports=[80, 443, 8080],
                rate_limit=1000,
                timeout_ms=5000,
            ),
            progress=ScanProgress(
                total_hosts=65536,
                scanned=12400,
                alive=3200,
                agents_found=47,
                percent_complete=18.9,
                current_ip="104.21.48.120",
            ),
            results_summary=ResultsSummary(
                total_endpoints=47,
                by_protocol={"mcp": 23, "openai_compat": 18},
                by_risk={"critical": 8, "high": 15},
                no_auth_count=31,
            ),
            endpoint_ids=["ep_001", "ep_002"],
            created_by="user_xyz",
        )
        assert s.id == "scan_001"
        assert s.config.target == "104.21.0.0/16"
        assert s.progress.agents_found == 47
        assert s.results_summary.no_auth_count == 31

    def test_ingestion_scan(self):
        s = Scan(
            type="ingestion",
            config=ScanConfig(source="shodan", query="mcp server", max_results=10000),
        )
        assert s.type == "ingestion"
        assert s.config.source == "shodan"

    def test_invalid_scan_type(self):
        with pytest.raises(ValidationError):
            Scan(type="unknown")

    def test_invalid_scan_status(self):
        with pytest.raises(ValidationError):
            Scan(status="exploded")

    def test_scan_create(self):
        sc = ScanCreate(
            name="Test Scan",
            config=ScanConfig(target="10.0.0.0/8", protocols=["mcp"]),
        )
        assert sc.name == "Test Scan"
        assert sc.type == "active"

    def test_serialization_to_dict(self):
        s = Scan(_id="scan_002", name="Test", status="completed")
        d = s.model_dump(by_alias=True)
        assert d["_id"] == "scan_002"
        assert d["status"] == "completed"
        assert isinstance(d["config"], dict)


# ═══════════════════════════════════════════════════════════════════
# MonitoredRange
# ═══════════════════════════════════════════════════════════════════


class TestMonitoredRange:
    """Tests for MonitoredRange and its nested models."""

    def test_minimal_valid(self):
        r = MonitoredRange(name="Test", cidr="10.0.0.0/8")
        assert r.cidr == "10.0.0.0/8"
        assert r.monitoring.enabled is False

    def test_full_valid(self):
        r = MonitoredRange(
            _id="range_xyz",
            name="Production AWS",
            cidr="104.21.0.0/16",
            total_hosts=65536,
            monitoring=MonitoringConfig(
                enabled=True,
                interval_hours=24,
                last_scan_id="scan_001",
            ),
            stats=RangeStats(
                total_endpoints=47,
                by_protocol={"mcp": 23, "openai_compat": 18, "langserve": 6},
                by_risk={"critical": 8, "high": 15, "medium": 12},
                no_auth_count=31,
                trend=Trend(
                    endpoints_7d_ago=35,
                    endpoints_30d_ago=12,
                    direction="increasing",
                ),
            ),
            scan_ids=["scan_001", "scan_002"],
            created_by="user_xyz",
            tags=["production", "aws"],
        )
        assert r.id == "range_xyz"
        assert r.monitoring.enabled is True
        assert r.stats.trend.direction == "increasing"
        assert r.stats.no_auth_count == 31

    def test_invalid_trend_direction(self):
        with pytest.raises(ValidationError):
            Trend(direction="sideways")

    def test_range_create(self):
        rc = RangeCreate(name="Dev", cidr="192.168.0.0/16")
        assert rc.name == "Dev"
        assert rc.total_hosts == 0

    def test_monitoring_config_interval_min(self):
        with pytest.raises(ValidationError):
            MonitoringConfig(interval_hours=0)

    def test_serialization_to_dict(self):
        r = MonitoredRange(_id="r_001", name="Test", cidr="10.0.0.0/24")
        d = r.model_dump(by_alias=True)
        assert d["_id"] == "r_001"
        assert d["cidr"] == "10.0.0.0/24"
        assert isinstance(d["monitoring"], dict)
        assert isinstance(d["stats"]["trend"], dict)


# ═══════════════════════════════════════════════════════════════════
# Cross-model imports from __init__
# ═══════════════════════════════════════════════════════════════════


class TestModelsInit:
    """Verify that all models are re-exported from app.models."""

    def test_all_exports_importable(self):
        from app.models import (
            AgentEndpoint,
            AgentEndpointCreate,
            AgentEndpointUpdate,
            AgentAnalysis,
            Fingerprint,
            ToolDetail,
            ScanRecord,
            Finding,
            TestingInfo,
            TestResult,
            ExploitationStep,
            AttackGraph,
            AttackNode,
            AttackEdge,
            Scan,
            ScanConfig,
            ScanCreate,
            ScanProgress,
            ResultsSummary,
            MonitoredRange,
            MonitoringConfig,
            RangeCreate,
            RangeStats,
            Trend,
            GeoInfo,
            ServerInfo,
            SourceRecord,
            ToolInfo,
        )
        # If we get here without ImportError, all exports are valid
        assert AgentEndpoint is not None
        assert Scan is not None
        assert MonitoredRange is not None
        assert AgentAnalysis is not None
