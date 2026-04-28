# AIMap Backend API

> REST + WebSocket API for discovering, browsing, and testing exposed AI agents.

Base URL: `http://localhost:8000/api`

---

## Health Check

### `GET /api/health`

Returns service health status.

**Response 200:**
```json
{
  "status": "ok",
  "service": "aimap-api"
}
```

---

## Endpoints

CRUD and search operations for discovered agent endpoints.

### `GET /api/endpoints`

List and filter endpoints with pagination.

**Query Parameters:**

| Parameter   | Type   | Default | Description                         |
|-------------|--------|---------|-------------------------------------|
| protocol    | string | —       | Filter by protocol (mcp, langserve, openai_compat, autogen) |
| auth_status | string | —       | Filter by auth status (none, api_key, oauth, etc.) |
| risk_min    | float  | —       | Minimum risk score (0.0–10.0)       |
| risk_max    | float  | —       | Maximum risk score (0.0–10.0)       |
| country     | string | —       | Filter by country code (e.g. US, DE) |
| tool        | string | —       | Filter by tool name                 |
| tag         | string | —       | Filter by tag                       |
| q           | string | —       | Full-text search query              |
| sort_by     | string | risk_score | Sort field (prefix with - for desc) |
| page        | int    | 1       | Page number (1-indexed)             |
| page_size   | int    | 25      | Results per page (1–100)            |

**Response 200:**
```json
{
  "items": [{ "id": "ep_abc123", "ip": "104.21.32.50", "port": 8080, ... }],
  "total": 847,
  "page": 1,
  "page_size": 25
}
```

### `GET /api/endpoints/stats`

Aggregation statistics for the dashboard.

**Response 200:**
```json
{
  "total": 12847,
  "by_protocol": { "mcp": 5400, "openai_compat": 3980, "langserve": 2310, "autogen": 1157 },
  "by_risk": { "critical": 3291, "high": 4102, "medium": 3200, "low": 1500, "info": 754 },
  "by_auth": { "none": 10073, "api_key": 1800, "oauth": 500, "unknown": 474 },
  "no_auth_count": 10073
}
```

### `GET /api/endpoints/geo`

Geographic aggregation for the map view.

**Response 200:**
```json
[
  { "country": "United States", "country_code": "US", "lat": 39.04, "lon": -77.49, "count": 5200 },
  { "country": "Germany", "country_code": "DE", "lat": 50.11, "lon": 8.68, "count": 1800 }
]
```

### `GET /api/endpoints/{endpoint_id}`

Get a single endpoint by ID.

**Response 200:** Full endpoint document with `id` field.
**Response 404:** `{"detail": "Endpoint not found"}`

### `POST /api/endpoints`

Create a new endpoint (used by the discovery engine).

**Request Body:** Endpoint document (JSON). If `_id` is omitted, one is auto-generated with the `ep_` prefix.

**Response 201:** Created endpoint document.
**Response 409:** `{"detail": "Endpoint already exists"}` (duplicate ip/port/protocol)

### `PUT /api/endpoints/{endpoint_id}`

Update an existing endpoint (partial update).

**Request Body:** Fields to update (JSON).

**Response 200:** Updated endpoint document.
**Response 404:** `{"detail": "Endpoint not found"}`

### `DELETE /api/endpoints/{endpoint_id}`

Delete an endpoint.

**Response 204:** No content.
**Response 404:** `{"detail": "Endpoint not found"}`

### `POST /api/endpoints/search`

Advanced search with Shodan-style query parsing.

**Request Body:**
```json
{
  "query": "protocol:mcp auth:none tool:query_db country:US"
}
```

**Query Parameters:**

| Parameter | Type | Default | Description       |
|-----------|------|---------|-------------------|
| page      | int  | 1       | Page number       |
| page_size | int  | 25      | Results per page  |

**Response 200:** Paginated results (same shape as `GET /api/endpoints`).

---

## Search Syntax

AIMap supports Shodan-style structured search queries. Structured filters and free text can be combined in a single query.

| Filter                | Example              | Description                              |
|-----------------------|----------------------|------------------------------------------|
| `protocol:<value>`    | `protocol:mcp`       | Filter by agent protocol                 |
| `auth:<value>`        | `auth:none`          | Filter by authentication status          |
| `risk:<level>`        | `risk:critical`      | Filter by risk level (critical/high/medium/low/info) |
| `tool:<name>`         | `tool:query_db`      | Filter by registered tool name           |
| `country:<code>`      | `country:US`         | Filter by ISO country code               |
| `port:<number>`       | `port:8080`          | Filter by port number                    |
| `org:"<name>"`        | `org:"Amazon AWS"`   | Filter by organization (quote spaces)    |
| `has:system_prompt`   | `has:system_prompt`  | Only endpoints with extracted system prompts |
| Free text             | `database assistant`  | Full-text search across hostname, tools, system prompt |

### Risk Level Mapping

| Level    | Score Range   |
|----------|---------------|
| critical | >= 9.0        |
| high     | 7.0 – 8.9    |
| medium   | 4.0 – 6.9    |
| low      | 1.0 – 3.9    |
| info     | < 1.0         |

### Examples

```
protocol:mcp auth:none
tool:query_db country:US risk:critical
org:"Amazon AWS" has:system_prompt
protocol:langserve database assistant
```

---

## Scans

Manage scan jobs (active scanning and 3P ingestion).

### `GET /api/scans`

List scans with filters.

**Query Parameters:**

| Parameter  | Type   | Default | Description                         |
|------------|--------|---------|-------------------------------------|
| status     | string | —       | Filter by status (queued, running, completed, failed, cancelled) |
| scan_type  | string | —       | Filter by type (active, ingestion)  |
| created_by | string | —       | Filter by creator                   |
| page       | int    | 1       | Page number                         |
| page_size  | int    | 25      | Results per page                    |

**Response 200:**
```json
{
  "items": [{ "id": "scan_abc123", "name": "AWS sweep", "status": "running", ... }],
  "total": 12,
  "page": 1,
  "page_size": 25
}
```

### `GET /api/scans/{scan_id}`

Get scan details.

**Response 200:** Full scan document.
**Response 404:** `{"detail": "Scan not found"}`

### `POST /api/scans`

Create a new scan.

**Request Body:**
```json
{
  "name": "AWS us-east-1 sweep",
  "type": "active",
  "config": {
    "target": "104.21.0.0/16",
    "protocols": ["mcp", "openai_compat"],
    "ports": [80, 443, 8080]
  },
  "created_by": "user_xyz"
}
```

**Response 201:** Created scan document with auto-generated ID and default progress/summary fields.

### `PUT /api/scans/{scan_id}/status`

Update scan status (pause, resume, stop).

**Request Body:**
```json
{
  "status": "paused"
}
```

Valid statuses: `queued`, `running`, `paused`, `stopped`, `completed`, `failed`.

**Response 200:** Updated scan document.
**Response 400:** Invalid status value.
**Response 404:** `{"detail": "Scan not found"}`

### `DELETE /api/scans/{scan_id}`

Delete a scan.

**Response 204:** No content.
**Response 404:** `{"detail": "Scan not found"}`

### `WebSocket /ws/scans/{scan_id}`

Stream scan progress in real time (placeholder).

**Protocol:**
1. Client connects to `ws://host/ws/scans/{scan_id}`
2. Server sends periodic JSON messages:
```json
{
  "type": "progress",
  "scan_id": "scan_abc123",
  "progress": {
    "scanned": 12400,
    "alive": 3200,
    "agents_found": 47,
    "percent_complete": 18.9
  }
}
```
3. On completion:
```json
{
  "type": "completed",
  "scan_id": "scan_abc123"
}
```

---

## Ranges

Manage monitored IP ranges.

### `GET /api/ranges`

List monitored ranges.

**Query Parameters:**

| Parameter  | Type   | Default | Description        |
|------------|--------|---------|--------------------|
| created_by | string | —       | Filter by creator  |
| page       | int    | 1       | Page number        |
| page_size  | int    | 25      | Results per page   |

**Response 200:**
```json
{
  "items": [{ "id": "range_xyz", "name": "Production AWS", "cidr": "104.21.0.0/16", ... }],
  "total": 5,
  "page": 1,
  "page_size": 25
}
```

### `GET /api/ranges/{range_id}`

Get range details with live endpoint count.

**Response 200:** Range document with additional `live_endpoint_count` field.
**Response 404:** `{"detail": "Range not found"}`

### `POST /api/ranges`

Create a monitored range.

**Request Body:**
```json
{
  "name": "Production AWS",
  "cidr": "104.21.0.0/16",
  "total_hosts": 65536,
  "created_by": "user_xyz",
  "tags": ["production", "aws"]
}
```

**Response 201:** Created range document.

### `PUT /api/ranges/{range_id}`

Update a range.

**Request Body:** Fields to update (JSON).

**Response 200:** Updated range document.
**Response 404:** `{"detail": "Range not found"}`

### `DELETE /api/ranges/{range_id}`

Delete a range.

**Response 204:** No content.
**Response 404:** `{"detail": "Range not found"}`

### `POST /api/ranges/{range_id}/scan`

Trigger a new scan for this range.

**Response 200:**
```json
{
  "scan_id": "scan_abc123",
  "range_id": "range_xyz",
  "status": "queued"
}
```

**Response 404:** `{"detail": "Range not found"}`

---

## Analyses

Deep-dive analysis and exploitation testing per endpoint.

### `GET /api/analyses/{endpoint_id}`

Get analysis for an endpoint.

**Response 200:** Full analysis document (fingerprint, scans, testing).
**Response 404:** `{"detail": "Analysis not found"}`

### `POST /api/analyses`

Create or update an analysis (upsert by `endpoint_id`).

**Request Body:**
```json
{
  "endpoint_id": "ep_abc123",
  "fingerprint": {
    "protocol_version": "MCP/1.0",
    "capabilities": ["tools", "prompts"],
    "tool_details": []
  }
}
```

**Response 201:** Created or updated analysis document.
**Response 400:** `{"detail": "endpoint_id is required"}`

### `GET /api/analyses/{endpoint_id}/testing`

Get test results for an endpoint.

**Response 200:**
```json
{
  "endpoint_id": "ep_abc123",
  "testing": {
    "status": "completed",
    "attack_surface": ["prompt_injection", "tool_injection"],
    "test_results": [...]
  }
}
```

**Response 404:** `{"detail": "Analysis not found"}`

### `WebSocket /ws/attack/{endpoint_id}`

Stream attack/exploitation progress in real time (placeholder).

**Protocol:**
1. Client connects to `ws://host/ws/attack/{endpoint_id}`
2. Server sends exploitation steps as JSON:
```json
{
  "type": "step",
  "step": 1,
  "reasoning": "Target has query_db + send_email with no auth.",
  "action": "Attempting system prompt extraction",
  "result": "System prompt extracted successfully"
}
```
3. On completion:
```json
{
  "type": "completed",
  "endpoint_id": "ep_abc123",
  "success": true
}
```
