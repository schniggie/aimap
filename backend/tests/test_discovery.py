"""Tests for the AIMap Discovery Engine.

Covers:
* Shodan adapter ``normalize()`` with sample Shodan response data.
* Shodan search query construction (predefined queries).
* NucleiRunner ``normalize_finding()`` with sample Nuclei JSONL output.
* Base adapter upsert logic (insert, merge sources, update ``last_seen``).
* Template YAML validity.

Run with::

    cd backend && source .venv/bin/activate && python -m pytest tests/test_discovery.py -v
"""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator
from unittest.mock import AsyncMock, MagicMock

import pytest
import yaml

# ---------------------------------------------------------------------------
# Ensure the backend package is importable regardless of cwd
# ---------------------------------------------------------------------------
BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

# Set a dummy Shodan key so the adapter can be instantiated in tests without
# hitting the real settings / .env file.
os.environ.setdefault("SHODAN_API_KEY", "test-key-not-real")

from app.discovery.base import SourceAdapter
from app.discovery.nuclei_runner import NucleiRunner
from app.discovery.shodan_adapter import AGENT_QUERIES, ShodanAdapter

# ---------------------------------------------------------------------------
# Project paths
# ---------------------------------------------------------------------------
PROJECT_ROOT = BACKEND_DIR.parent
TEMPLATES_DIR = PROJECT_ROOT / "templates"


# ===================================================================
# Fixtures
# ===================================================================

@pytest.fixture
def sample_shodan_result() -> dict:
    """A realistic Shodan search result dict."""
    return {
        "ip_str": "104.21.32.50",
        "port": 8080,
        "hostnames": ["agent.example.com"],
        "data": (
            "HTTP/1.1 200 OK\r\n"
            "Server: uvicorn/0.29.0\r\n"
            "Content-Type: application/json\r\n"
            'Access-Control-Allow-Origin: *\r\n'
            "\r\n"
            '{"jsonrpc":"2.0","result":{"capabilities":{"tools":true}}}'
        ),
        "http": {
            "status": 200,
            "headers": {
                "Server": "uvicorn/0.29.0",
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
            },
            "html": '{"jsonrpc":"2.0","result":{"capabilities":{"tools":true}}}',
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
        "ssl": None,
    }


@pytest.fixture
def sample_shodan_result_openai() -> dict:
    """Shodan result that looks like an OpenAI-compatible endpoint."""
    return {
        "ip_str": "52.14.88.200",
        "port": 3000,
        "hostnames": ["llm.corp.io"],
        "data": (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "Location: /v1/models\r\n"
            "\r\n"
            '{"object":"list","data":[{"id":"gpt-4","object":"model"}]}'
        ),
        "http": {
            "status": 200,
            "headers": {"Content-Type": "application/json"},
            "html": '{"object":"list","data":[{"id":"gpt-4","object":"model"}]} /v1/models',
        },
        "location": {
            "country_name": "Germany",
            "country_code": "DE",
            "region_code": "HE",
            "city": "Frankfurt",
            "latitude": 50.1109,
            "longitude": 8.6821,
        },
        "asn": "AS16509",
        "org": "Amazon AWS",
        "ssl": {"cert": {}},
    }


@pytest.fixture
def sample_nuclei_finding() -> dict:
    """A realistic Nuclei JSONL finding dict."""
    return {
        "template-id": "mcp-server-detect",
        "info": {
            "name": "MCP Server Detection",
            "severity": "info",
            "tags": ["mcp", "agent", "discovery"],
        },
        "type": "http",
        "host": "http://104.21.32.50:8080",
        "matched-at": "http://104.21.32.50:8080/",
        "ip": "104.21.32.50",
        "port": "8080",
        "timestamp": "2026-03-14T08:05:00.000Z",
        "matcher-name": "mcp-capabilities",
        "extracted-results": ['{"capabilities":{"tools":true}}'],
        "curl-command": "curl -X POST http://104.21.32.50:8080/ ...",
    }


@pytest.fixture
def sample_nuclei_finding_openai() -> dict:
    """Nuclei finding for an OpenAI-compatible endpoint."""
    return {
        "template-id": "openai-compat-detect",
        "info": {
            "name": "OpenAI-Compatible API Detection",
            "severity": "info",
            "tags": ["openai", "agent", "discovery"],
        },
        "type": "http",
        "host": "https://llm.corp.io:443",
        "matched-at": "https://llm.corp.io:443/v1/models",
        "ip": "52.14.88.200",
        "port": "443",
        "timestamp": "2026-03-14T08:10:00.000Z",
    }


# ===================================================================
# Helper: in-memory MongoDB mock
# ===================================================================

class MockCollection:
    """Minimal async mock of a motor collection with find_one/insert_one/update_one."""

    def __init__(self) -> None:
        self._docs: list[dict[str, Any]] = []

    async def find_one(self, filter_: dict) -> dict | None:
        for doc in self._docs:
            if all(doc.get(k) == v for k, v in filter_.items()):
                return dict(doc)  # return a copy
        return None

    async def insert_one(self, doc: dict) -> MagicMock:
        self._docs.append(dict(doc))
        result = MagicMock()
        result.inserted_id = doc.get("_id")
        return result

    async def update_one(self, filter_: dict, update: dict) -> MagicMock:
        for doc in self._docs:
            if all(doc.get(k) == v for k, v in filter_.items()):
                set_fields = update.get("$set", {})
                doc.update(set_fields)
                result = MagicMock()
                result.modified_count = 1
                return result
        result = MagicMock()
        result.modified_count = 0
        return result


class MockDB:
    """Minimal async mock of a motor database."""

    def __init__(self) -> None:
        self._collections: dict[str, MockCollection] = {}

    def __getitem__(self, name: str) -> MockCollection:
        if name not in self._collections:
            self._collections[name] = MockCollection()
        return self._collections[name]


# ===================================================================
# Concrete adapter subclass for testing the base class
# ===================================================================

class FakeAdapter(SourceAdapter):
    """Concrete implementation of SourceAdapter for testing the base class."""

    def __init__(self, results: list[dict] | None = None) -> None:
        self._results = results or []

    @property
    def source_name(self) -> str:
        return "fake"

    async def search(self, query: str, max_results: int = 100) -> AsyncIterator[dict]:
        for r in self._results[:max_results]:
            yield r

    def normalize(self, raw: dict) -> dict:
        return raw


# ===================================================================
# Tests: Shodan adapter normalize()
# ===================================================================

class TestShodanNormalize:
    """Test ShodanAdapter.normalize() with sample data."""

    def setup_method(self) -> None:
        self.adapter = ShodanAdapter(api_key="test-key")

    def test_basic_fields(self, sample_shodan_result: dict) -> None:
        result = self.adapter.normalize(sample_shodan_result)
        assert result["ip"] == "104.21.32.50"
        assert result["port"] == 8080
        assert result["hostname"] == "agent.example.com"

    def test_url_construction_http(self, sample_shodan_result: dict) -> None:
        result = self.adapter.normalize(sample_shodan_result)
        # No SSL -> http
        assert result["url"] == "http://agent.example.com:8080"

    def test_url_construction_https(self, sample_shodan_result_openai: dict) -> None:
        result = self.adapter.normalize(sample_shodan_result_openai)
        assert result["url"].startswith("https://")

    def test_geo_mapping(self, sample_shodan_result: dict) -> None:
        result = self.adapter.normalize(sample_shodan_result)
        geo = result["geo"]
        assert geo["country"] == "United States"
        assert geo["country_code"] == "US"
        assert geo["city"] == "Ashburn"
        assert geo["lat"] == 39.0438
        assert geo["lon"] == -77.4874
        assert geo["asn"] == "AS14618"
        assert geo["org"] == "Amazon.com, Inc."

    def test_server_info(self, sample_shodan_result: dict) -> None:
        result = self.adapter.normalize(sample_shodan_result)
        server = result["server"]
        assert server["banner"] == "uvicorn/0.29.0"
        assert server["tls"] is False

    def test_cors_detection(self, sample_shodan_result: dict) -> None:
        result = self.adapter.normalize(sample_shodan_result)
        assert result["server"]["cors_open"] is True

    def test_tls_detection(self, sample_shodan_result_openai: dict) -> None:
        result = self.adapter.normalize(sample_shodan_result_openai)
        assert result["server"]["tls"] is True

    def test_protocol_detection_mcp(self, sample_shodan_result: dict) -> None:
        result = self.adapter.normalize(sample_shodan_result)
        assert result["protocol"] == "mcp"

    def test_protocol_detection_openai(self, sample_shodan_result_openai: dict) -> None:
        result = self.adapter.normalize(sample_shodan_result_openai)
        assert result["protocol"] == "openai_compat"

    def test_auth_status_default(self, sample_shodan_result: dict) -> None:
        result = self.adapter.normalize(sample_shodan_result)
        assert result["auth_status"] == "unknown"

    def test_source_record(self, sample_shodan_result: dict) -> None:
        result = self.adapter.normalize(sample_shodan_result)
        assert len(result["sources"]) == 1
        src = result["sources"][0]
        assert src["source"] == "shodan"
        assert "discovered_at" in src
        assert src["raw_data"] == sample_shodan_result

    def test_missing_hostname(self) -> None:
        raw = {
            "ip_str": "10.0.0.1",
            "port": 443,
            "hostnames": [],
            "data": "",
            "http": {},
            "location": {},
            "ssl": {"cert": {}},
        }
        result = self.adapter.normalize(raw)
        assert result["hostname"] == ""
        assert "10.0.0.1" in result["url"]


# ===================================================================
# Tests: Shodan search query construction
# ===================================================================

class TestShodanQueries:
    """Test predefined Shodan search queries."""

    def test_agent_queries_exist(self) -> None:
        queries = ShodanAdapter.get_agent_queries()
        assert isinstance(queries, dict)
        assert len(queries) > 0

    def test_expected_query_keys(self) -> None:
        queries = ShodanAdapter.get_agent_queries()
        expected = {"mcp_protocol", "ollama", "langserve"}
        assert expected.issubset(set(queries.keys()))

    def test_queries_are_strings(self) -> None:
        queries = ShodanAdapter.get_agent_queries()
        for key, query in queries.items():
            assert isinstance(query, str), f"Query {key} is not a string"
            assert len(query) > 0, f"Query {key} is empty"

    def test_queries_module_constant(self) -> None:
        assert isinstance(AGENT_QUERIES, dict)
        assert "mcp" in AGENT_QUERIES


# ===================================================================
# Tests: NucleiRunner normalize_finding()
# ===================================================================

class TestNucleiNormalize:
    """Test NucleiRunner.normalize_finding() with sample JSONL data."""

    def setup_method(self) -> None:
        self.runner = NucleiRunner()

    def test_basic_fields(self, sample_nuclei_finding: dict) -> None:
        result = self.runner.normalize_finding(sample_nuclei_finding)
        assert result["ip"] == "104.21.32.50"
        assert result["port"] == 8080
        assert result["url"] == "http://104.21.32.50:8080"

    def test_protocol_from_template(self, sample_nuclei_finding: dict) -> None:
        result = self.runner.normalize_finding(sample_nuclei_finding)
        assert result["protocol"] == "mcp"

    def test_protocol_openai(self, sample_nuclei_finding_openai: dict) -> None:
        result = self.runner.normalize_finding(sample_nuclei_finding_openai)
        assert result["protocol"] == "openai_compat"

    def test_source_record(self, sample_nuclei_finding: dict) -> None:
        result = self.runner.normalize_finding(sample_nuclei_finding)
        assert len(result["sources"]) == 1
        src = result["sources"][0]
        assert src["source"] == "nuclei"
        assert src["template"] == "mcp-server-detect"
        assert "discovered_at" in src
        assert src["raw_data"] is sample_nuclei_finding

    def test_port_extraction_from_host(self) -> None:
        finding = {
            "template-id": "langserve-detect",
            "info": {"name": "test", "severity": "info", "tags": ["langserve"]},
            "host": "https://example.com:9090/docs",
            "ip": "1.2.3.4",
            "port": "",
        }
        result = self.runner.normalize_finding(finding)
        assert result["port"] == 9090

    def test_port_default_https(self) -> None:
        finding = {
            "template-id": "test",
            "info": {"name": "test", "severity": "info", "tags": []},
            "host": "https://example.com",
            "ip": "1.2.3.4",
            "port": "",
        }
        result = self.runner.normalize_finding(finding)
        assert result["port"] == 443

    def test_port_default_http(self) -> None:
        finding = {
            "template-id": "test",
            "info": {"name": "test", "severity": "info", "tags": []},
            "host": "http://example.com",
            "ip": "1.2.3.4",
            "port": "",
        }
        result = self.runner.normalize_finding(finding)
        assert result["port"] == 80


# ===================================================================
# Tests: Base adapter upsert logic
# ===================================================================

class TestBaseAdapterUpsert:
    """Test SourceAdapter.ingest() upsert logic using FakeAdapter."""

    @pytest.mark.asyncio
    async def test_insert_new_endpoint(self) -> None:
        """A new endpoint should be inserted into the collection."""
        adapter = FakeAdapter(results=[
            {
                "ip": "10.0.0.1",
                "port": 8080,
                "protocol": "mcp",
                "hostname": "test.example.com",
                "sources": [{"source": "fake", "discovered_at": "2026-01-01T00:00:00Z"}],
            }
        ])
        db = MockDB()
        ids = await adapter.ingest("test", 10, db)

        assert len(ids) == 1
        assert ids[0].startswith("ep_")

        # Verify the document was inserted
        doc = await db["endpoints"].find_one({"ip": "10.0.0.1", "port": 8080})
        assert doc is not None
        assert doc["hostname"] == "test.example.com"
        assert doc["protocol"] == "mcp"

    @pytest.mark.asyncio
    async def test_merge_existing_endpoint(self) -> None:
        """When an endpoint already exists, sources should be merged."""
        db = MockDB()
        collection = db["endpoints"]

        # Pre-insert an existing document
        existing = {
            "_id": "ep_existing123",
            "ip": "10.0.0.1",
            "port": 8080,
            "hostname": "",
            "protocol": "mcp",
            "geo": {},
            "server": {},
            "sources": [
                {"source": "shodan", "discovered_at": "2026-01-01T00:00:00Z"}
            ],
            "last_seen": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }
        await collection.insert_one(existing)

        # Ingest new data for the same IP:port
        adapter = FakeAdapter(results=[
            {
                "ip": "10.0.0.1",
                "port": 8080,
                "hostname": "enriched.example.com",
                "protocol": "mcp",
                "sources": [{"source": "censys", "discovered_at": "2026-02-01T00:00:00Z"}],
            }
        ])
        ids = await adapter.ingest("test", 10, db)

        assert len(ids) == 1
        assert ids[0] == "ep_existing123"

        # Verify merge
        doc = await collection.find_one({"_id": "ep_existing123"})
        assert doc is not None
        # hostname should be updated because existing was empty
        assert doc["hostname"] == "enriched.example.com"
        # sources should contain both
        assert len(doc["sources"]) == 2
        source_names = [s["source"] for s in doc["sources"]]
        assert "shodan" in source_names
        assert "censys" in source_names

    @pytest.mark.asyncio
    async def test_merge_does_not_overwrite_richer_data(self) -> None:
        """Merge should not overwrite non-empty fields with empty ones."""
        db = MockDB()
        collection = db["endpoints"]

        existing = {
            "_id": "ep_rich123",
            "ip": "10.0.0.2",
            "port": 443,
            "hostname": "already-known.com",
            "protocol": "openai_compat",
            "framework": "vllm",
            "geo": {"country": "US"},
            "server": {"banner": "nginx"},
            "sources": [],
            "last_seen": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }
        await collection.insert_one(existing)

        adapter = FakeAdapter(results=[
            {
                "ip": "10.0.0.2",
                "port": 443,
                "hostname": "",  # empty -- should NOT overwrite
                "protocol": "mcp",  # different but existing has value -- should NOT overwrite
                "framework": "",  # empty -- should NOT overwrite
                "sources": [{"source": "fake"}],
            }
        ])
        ids = await adapter.ingest("test", 10, db)

        doc = await collection.find_one({"_id": "ep_rich123"})
        assert doc["hostname"] == "already-known.com"
        assert doc["protocol"] == "openai_compat"  # NOT overwritten

    @pytest.mark.asyncio
    async def test_update_last_seen(self) -> None:
        """Merge should always update last_seen and updated_at."""
        db = MockDB()
        collection = db["endpoints"]

        old_time = "2025-01-01T00:00:00Z"
        existing = {
            "_id": "ep_time123",
            "ip": "10.0.0.3",
            "port": 80,
            "hostname": "",
            "protocol": "mcp",
            "geo": {},
            "server": {},
            "sources": [],
            "last_seen": old_time,
            "updated_at": old_time,
        }
        await collection.insert_one(existing)

        adapter = FakeAdapter(results=[
            {"ip": "10.0.0.3", "port": 80, "protocol": "mcp", "sources": []}
        ])
        await adapter.ingest("test", 10, db)

        doc = await collection.find_one({"_id": "ep_time123"})
        assert doc["last_seen"] != old_time
        assert doc["updated_at"] != old_time

    @pytest.mark.asyncio
    async def test_replace_same_source(self) -> None:
        """Merging a source with the same name should replace, not duplicate."""
        db = MockDB()
        collection = db["endpoints"]

        existing = {
            "_id": "ep_src123",
            "ip": "10.0.0.4",
            "port": 8080,
            "hostname": "",
            "protocol": "mcp",
            "geo": {},
            "server": {},
            "sources": [
                {"source": "shodan", "discovered_at": "2026-01-01T00:00:00Z", "raw_data": {"old": True}}
            ],
            "last_seen": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }
        await collection.insert_one(existing)

        adapter = FakeAdapter(results=[
            {
                "ip": "10.0.0.4",
                "port": 8080,
                "protocol": "mcp",
                "sources": [
                    {"source": "shodan", "discovered_at": "2026-03-01T00:00:00Z", "raw_data": {"new": True}}
                ],
            }
        ])
        await adapter.ingest("test", 10, db)

        doc = await collection.find_one({"_id": "ep_src123"})
        # Should have exactly 1 shodan source, the new one
        shodan_sources = [s for s in doc["sources"] if s["source"] == "shodan"]
        assert len(shodan_sources) == 1
        assert shodan_sources[0]["raw_data"] == {"new": True}

    @pytest.mark.asyncio
    async def test_skip_missing_ip_port(self) -> None:
        """Results with missing ip or port should be skipped."""
        adapter = FakeAdapter(results=[
            {"ip": "", "port": 80, "protocol": "mcp"},
            {"ip": "10.0.0.1", "port": None, "protocol": "mcp"},
        ])
        db = MockDB()
        ids = await adapter.ingest("test", 10, db)
        assert len(ids) == 0

    @pytest.mark.asyncio
    async def test_multiple_results_ingest(self) -> None:
        """Multiple different results should each be inserted."""
        adapter = FakeAdapter(results=[
            {"ip": "10.0.0.1", "port": 80, "protocol": "mcp", "sources": []},
            {"ip": "10.0.0.2", "port": 443, "protocol": "openai_compat", "sources": []},
            {"ip": "10.0.0.3", "port": 8080, "protocol": "langserve", "sources": []},
        ])
        db = MockDB()
        ids = await adapter.ingest("test", 100, db)
        assert len(ids) == 3
        assert len(set(ids)) == 3  # all unique


# ===================================================================
# Tests: Template YAML validity
# ===================================================================

class TestTemplateValidity:
    """Verify that all YAML templates in the templates/ directory are valid."""

    def _get_template_files(self) -> list[Path]:
        """Return all .yaml/.yml files under templates/."""
        if not TEMPLATES_DIR.is_dir():
            pytest.skip(f"Templates directory not found: {TEMPLATES_DIR}")
        files = list(TEMPLATES_DIR.glob("*.yaml")) + list(TEMPLATES_DIR.glob("*.yml"))
        if not files:
            pytest.skip("No template files found")
        return files

    def test_templates_are_valid_yaml(self) -> None:
        for path in self._get_template_files():
            with open(path, "r") as fh:
                data = yaml.safe_load(fh)
            assert data is not None, f"Template {path.name} parsed as None"
            assert isinstance(data, dict), f"Template {path.name} is not a mapping"

    def test_templates_have_required_fields(self) -> None:
        for path in self._get_template_files():
            with open(path, "r") as fh:
                data = yaml.safe_load(fh)
            assert "id" in data, f"Template {path.name} missing 'id'"
            assert "info" in data, f"Template {path.name} missing 'info'"
            info = data["info"]
            assert "name" in info, f"Template {path.name} missing 'info.name'"
            assert "severity" in info, f"Template {path.name} missing 'info.severity'"

    def test_templates_have_http_section(self) -> None:
        for path in self._get_template_files():
            with open(path, "r") as fh:
                data = yaml.safe_load(fh)
            assert "http" in data, f"Template {path.name} missing 'http' section"
            assert isinstance(data["http"], list), f"Template {path.name}: 'http' should be a list"
            assert len(data["http"]) > 0, f"Template {path.name}: 'http' list is empty"

    def test_expected_templates_exist(self) -> None:
        expected = {
            "mcp-server-detect.yaml",
            "mcp-tool-enum.yaml",
            "openai-compat-detect.yaml",
            "langserve-detect.yaml",
            "prompt-leak.yaml",
        }
        actual = {p.name for p in self._get_template_files()}
        missing = expected - actual
        assert not missing, f"Missing template files: {missing}"

    def test_template_severities_valid(self) -> None:
        valid_severities = {"info", "low", "medium", "high", "critical"}
        for path in self._get_template_files():
            with open(path, "r") as fh:
                data = yaml.safe_load(fh)
            severity = data["info"]["severity"]
            assert severity in valid_severities, (
                f"Template {path.name} has invalid severity: {severity}"
            )

    def test_template_tags_present(self) -> None:
        for path in self._get_template_files():
            with open(path, "r") as fh:
                data = yaml.safe_load(fh)
            tags = data["info"].get("tags")
            assert tags, f"Template {path.name} missing tags"
