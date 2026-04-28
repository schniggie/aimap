# Discovery Engine

The Discovery Engine is the data ingestion backbone of AIMap.  It discovers
exposed AI agents from third-party sources (Shodan, Censys, ...) and through
active scanning (httpx + Nuclei), normalizes every finding into the unified
`AgentEndpoint` schema, and upserts the result into MongoDB.

---

## Table of Contents

1. [Adapter Interface](#adapter-interface)
2. [Adding a New Source](#adding-a-new-source)
3. [Shodan Adapter](#shodan-adapter)
4. [Censys Adapter (stub)](#censys-adapter-stub)
5. [Nuclei Templates](#nuclei-templates)
6. [Nuclei Runner](#nuclei-runner)
7. [Scan Orchestrator](#scan-orchestrator)
8. [Example: Shodan Response to Normalized Endpoint](#example-shodan-response-to-normalized-endpoint)

---

## Adapter Interface

Every third-party data source implements `SourceAdapter` (defined in
`backend/app/discovery/base.py`).

```python
class SourceAdapter(ABC):
    @property
    @abstractmethod
    def source_name(self) -> str: ...

    @abstractmethod
    async def search(self, query: str, max_results: int) -> AsyncIterator[dict]: ...

    @abstractmethod
    def normalize(self, raw: dict) -> dict: ...

    async def ingest(self, query: str, max_results: int, db) -> list[str]: ...
```

### Methods

| Method | Responsibility |
|--------|----------------|
| `source_name` | Short identifier (e.g. `"shodan"`). Used in source records. |
| `search()` | Async generator that yields raw result dicts from the upstream API. |
| `normalize()` | Converts one raw result into an `AgentEndpoint`-compatible dict. |
| `ingest()` | Full pipeline: search -> normalize -> upsert to MongoDB. Returns list of endpoint `_id` values. Provided by the base class. |

### Upsert Logic

On ingest, the adapter looks up existing documents by `(ip, port)`:

* **If the document exists:**
  * The new source entry is appended to `sources` (or replaces an existing
    entry for the same source name).
  * `last_seen` and `updated_at` are bumped to the current time.
  * Top-level fields (`hostname`, `url`, `framework`, `model`, `protocol`)
    are updated **only** when the incoming value is truthy and the existing
    value is falsy/empty.
  * Geo and server info are updated only when the incoming data is richer.

* **If the document does not exist:** a fresh document is inserted with a
  generated `ep_*` ID.

---

## Adding a New Source

1. Create a new file: `backend/app/discovery/<source>_adapter.py`.
2. Subclass `SourceAdapter`.
3. Implement `source_name`, `search()`, and `normalize()`.
4. Register the adapter in `backend/app/discovery/orchestrator.py`:

```python
from app.discovery.my_source_adapter import MySourceAdapter

_ADAPTER_REGISTRY["my_source"] = MySourceAdapter
```

5. Add tests in `backend/tests/test_discovery.py`.
6. Add the required SDK/credentials to `requirements.txt` and `app/config.py`.

### Normalize Contract

The `normalize()` method must return a dict with at minimum:

```python
{
    "ip": "1.2.3.4",
    "port": 8080,
    "protocol": "mcp",          # one of: mcp, openai_compat, langserve, autogen
    "sources": [
        {
            "source": "my_source",
            "discovered_at": "2026-03-14T08:00:00Z",
            "raw_data": { ... }
        }
    ]
}
```

Optional but recommended fields: `hostname`, `url`, `geo`, `server`,
`auth_status`, `framework`, `model`.

---

## Shodan Adapter

**File:** `backend/app/discovery/shodan_adapter.py`

### Configuration

Requires `SHODAN_API_KEY` in the environment (set in `.env`).

### Predefined Queries

| Key | Query | What It Finds |
|-----|-------|---------------|
| `mcp` | `"jsonrpc" "capabilities" "tools"` | MCP servers responding with JSON-RPC |
| `mcp_initialize` | `"method" "initialize" "jsonrpc"` | MCP initialize handshakes |
| `openai_compat` | `"/v1/models" "object" "data"` | OpenAI-compatible model listing |
| `openai_chat` | `"/v1/chat/completions" "openai"` | OpenAI chat endpoints |
| `langserve` | `"langserve" "/docs"` | LangServe with Swagger docs |
| `langserve_invoke` | `"/invoke" "langchain"` | LangServe invoke endpoints |
| `fastapi_agent` | `"FastAPI" "/docs" "agent"` | FastAPI-based agent APIs |
| `generic_agent` | `"AI" "agent" "/api"` | Broad agent detection |

### Field Mapping

| Shodan Field | AgentEndpoint Field |
|--------------|---------------------|
| `ip_str` | `ip` |
| `port` | `port` |
| `hostnames[0]` | `hostname` |
| `location.country_name` | `geo.country` |
| `location.country_code` | `geo.country_code` |
| `location.region_code` | `geo.region` |
| `location.city` | `geo.city` |
| `location.latitude` | `geo.lat` |
| `location.longitude` | `geo.lon` |
| `asn` | `geo.asn` |
| `org` | `geo.org` |
| `http.headers.Server` | `server.banner` |
| `http.headers` | `server.headers` |
| `ssl` (truthy check) | `server.tls` |
| `http.headers.Access-Control-Allow-Origin == "*"` | `server.cors_open` |

### Protocol Detection

The adapter inspects the banner and HTTP response body:

* Contains `jsonrpc` + `capabilities` -> `mcp`
* Contains `/v1/models` or `/v1/chat/completions` -> `openai_compat`
* Contains `langserve` or (`/invoke` + `langchain`) -> `langserve`
* Contains `autogen` -> `autogen`
* Fallback: `mcp`

### Limitations

* Auth status is always `"unknown"` -- active probing is required to determine
  actual authentication requirements.
* Rate limited to ~1 request/second (Shodan basic plan).
* Tool enumeration requires active scanning (Nuclei templates).
* Banner-based protocol detection is heuristic and may produce false positives.

---

## Censys Adapter (stub)

**File:** `backend/app/discovery/censys_adapter.py`

Skeleton with `NotImplementedError` in all methods.  See the docstrings in the
file for the complete field mapping from Censys to AgentEndpoint.

Requires `CENSYS_API_ID` and `CENSYS_API_SECRET`.

---

## Nuclei Templates

Custom YAML templates live in `templates/` at the project root.

### Template Inventory

| File | What It Detects | Severity |
|------|-----------------|----------|
| `mcp-server-detect.yaml` | MCP servers via JSON-RPC `initialize` | info |
| `mcp-tool-enum.yaml` | Exposed MCP tools via `tools/list` | medium |
| `openai-compat-detect.yaml` | OpenAI-compatible APIs (`/v1/models`, `/v1/chat/completions`) | info |
| `langserve-detect.yaml` | LangServe deployments (`/docs`, `/invoke`, `/openapi.json`) | info |
| `prompt-leak.yaml` | System prompt leakage via injection techniques | high |

### How Each Template Works

**mcp-server-detect.yaml**
Sends an HTTP POST with a JSON-RPC 2.0 `initialize` request to `/`, `/mcp`,
and `/sse`.  Matches when the response contains both `"jsonrpc"` and
`"capabilities"`.  Extracts server name, protocol version, and capabilities.

**mcp-tool-enum.yaml**
Sends a `tools/list` JSON-RPC request.  Matches when the response contains
`"jsonrpc"` and `"tools"`.  Extracts the full tool listing.  Severity is
`medium` because exposed tools represent meaningful information disclosure.

**openai-compat-detect.yaml**
Probe 1: `GET /v1/models` -- matches on `"object"` and `"data"` (OpenAI list
response shape).  Probe 2: `POST /v1/chat/completions` with a minimal payload
-- matches on either a success response (`"choices"`) or an error that still
confirms it is an OpenAI-compatible API.

**langserve-detect.yaml**
Probe 1: `GET /docs` -- matches on Swagger/FastAPI presence.  Probe 2:
`POST /invoke` with `{"input":{}}` -- matches on LangServe response patterns
or FastAPI validation errors.  Probe 3: `GET /openapi.json` -- extracts API
path listing.

**prompt-leak.yaml**
Four techniques: (1) MCP tool call injection, (2) OpenAI chat completions
prompt extraction, (3) markdown formatting trick, (4) LangServe invoke
injection.  Matches on common system prompt patterns (`"you are"`,
`"instructions"`, etc.).  Severity is `high`.

### Adding a New Template

1. Create a YAML file in `templates/` following the Nuclei template format.
2. Required fields: `id`, `info.name`, `info.severity`, `info.tags`, `http`.
3. Tag with relevant protocol identifiers (`mcp`, `openai`, `langserve`, etc.).
4. Add a test case in `test_discovery.py` if the template is expected.
5. The scan orchestrator will automatically pick up all templates in the
   configured templates directory.

---

## Nuclei Runner

**File:** `backend/app/discovery/nuclei_runner.py`

### Class: `NucleiRunner`

Wraps the `nuclei` CLI binary as an async subprocess.

| Method | Description |
|--------|-------------|
| `check_nuclei()` | Verifies the nuclei binary is available on `$PATH`. |
| `run_scan(targets_file, templates_dir, output_file)` | Runs nuclei, returns parsed findings. |
| `normalize_finding(finding)` | Converts a Nuclei JSONL finding to an `AgentEndpoint`-compatible dict. |

### Finding Normalization

| Nuclei JSONL Field | AgentEndpoint Field |
|--------------------|---------------------|
| `ip` | `ip` |
| `port` | `port` |
| `host` | `url` |
| `template-id` | `sources[0].template` |
| `timestamp` | `sources[0].discovered_at` |
| `info.tags` | Used for protocol detection |
| Full finding | `sources[0].raw_data` |

---

## Scan Orchestrator

**File:** `backend/app/discovery/orchestrator.py`

### Class: `ScanOrchestrator`

Coordinates the full scanning pipeline.

### Scan Types

**Ingestion Scan** (`type: "ingestion"`)
1. Instantiate the appropriate `SourceAdapter` (by `config.source`).
2. Call `adapter.ingest(query, max_results, db)`.
3. Return the list of upserted endpoint IDs.

**Active Scan** (`type: "active"`)
1. Write target CIDR/hosts to a temp file.
2. Run `httpx` as a subprocess for alive-host discovery.
3. Parse alive hosts from httpx JSON output.
4. Write alive hosts to a temp file.
5. Run `nuclei` with AIMap templates against alive hosts.
6. Parse Nuclei JSONL findings.
7. Normalize each finding and upsert into MongoDB.
8. Clean up temp files.
9. Call `progress_callback` at each phase transition.

### Progress Callback

The orchestrator accepts an optional `async progress_callback(dict)` that
receives progress updates at each phase:

```python
{"phase": "httpx",  "status": "started",   "target": "10.0.0.0/24"}
{"phase": "httpx",  "status": "completed", "alive_count": 42}
{"phase": "nuclei", "status": "started",   "target_count": 42}
{"phase": "nuclei", "status": "completed", "findings_count": 7}
{"phase": "complete","status": "completed", "total_endpoints": 7}
```

---

## Example: Shodan Response to Normalized Endpoint

### Raw Shodan Result

```json
{
  "ip_str": "104.21.32.50",
  "port": 8080,
  "hostnames": ["agent.example.com"],
  "data": "HTTP/1.1 200 OK\r\nServer: uvicorn/0.29.0\r\n...\r\n{\"jsonrpc\":\"2.0\",\"result\":{\"capabilities\":{\"tools\":true}}}",
  "http": {
    "status": 200,
    "headers": {
      "Server": "uvicorn/0.29.0",
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*"
    },
    "html": "{\"jsonrpc\":\"2.0\",\"result\":{\"capabilities\":{\"tools\":true}}}"
  },
  "location": {
    "country_name": "United States",
    "country_code": "US",
    "region_code": "VA",
    "city": "Ashburn",
    "latitude": 39.0438,
    "longitude": -77.4874
  },
  "asn": "AS14618",
  "org": "Amazon.com, Inc.",
  "ssl": null
}
```

### Normalized Output

```json
{
  "ip": "104.21.32.50",
  "port": 8080,
  "hostname": "agent.example.com",
  "url": "http://agent.example.com:8080",
  "protocol": "mcp",
  "auth_status": "unknown",
  "geo": {
    "country": "United States",
    "country_code": "US",
    "region": "VA",
    "city": "Ashburn",
    "lat": 39.0438,
    "lon": -77.4874,
    "asn": "AS14618",
    "org": "Amazon.com, Inc."
  },
  "server": {
    "banner": "uvicorn/0.29.0",
    "headers": {
      "Server": "uvicorn/0.29.0",
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*"
    },
    "tls": false,
    "cors_open": true
  },
  "sources": [
    {
      "source": "shodan",
      "discovered_at": "2026-03-14T12:00:00+00:00",
      "raw_data": { "...full Shodan result..." }
    }
  ]
}
```

### After Upsert (MongoDB Document)

```json
{
  "_id": "ep_a1b2c3d4e5f6",
  "ip": "104.21.32.50",
  "port": 8080,
  "hostname": "agent.example.com",
  "url": "http://agent.example.com:8080",
  "protocol": "mcp",
  "framework": "",
  "model": "",
  "auth_status": "unknown",
  "tools": [],
  "tool_count": 0,
  "dangerous_combos": [],
  "system_prompt": "",
  "system_prompt_extracted": false,
  "risk_score": 0.0,
  "risk_factors": [],
  "geo": {
    "country": "United States",
    "country_code": "US",
    "region": "VA",
    "city": "Ashburn",
    "lat": 39.0438,
    "lon": -77.4874,
    "asn": "AS14618",
    "org": "Amazon.com, Inc."
  },
  "server": {
    "banner": "uvicorn/0.29.0",
    "headers": { "..." },
    "tls": false,
    "cors_open": true
  },
  "sources": [
    {
      "source": "shodan",
      "discovered_at": "2026-03-14T12:00:00+00:00",
      "raw_data": {}
    }
  ],
  "range_id": null,
  "scan_ids": [],
  "analysis_id": null,
  "first_seen": "2026-03-14T12:00:00+00:00",
  "last_seen": "2026-03-14T12:00:00+00:00",
  "created_at": "2026-03-14T12:00:00+00:00",
  "updated_at": "2026-03-14T12:00:00+00:00",
  "tags": []
}
```
