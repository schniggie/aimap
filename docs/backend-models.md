# Backend Models & Data Layer

Documentation for the AIMap backend data layer: configuration, database, and Pydantic models.

---

## Configuration (`backend/app/config.py`)

Uses `pydantic-settings` to load from environment variables and/or a `.env` file.

| Setting | Type | Default | Purpose |
|---------|------|---------|---------|
| `SHODAN_API_KEY` | str | `""` | API key for Shodan 3P ingestion |
| `CENSYS_API_ID` | str | `""` | Censys API ID for search queries |
| `CENSYS_API_SECRET` | str | `""` | Censys API secret for authentication |
| `ANTHROPIC_API_KEY` | str | `""` | Claude API key for the exploitation engine |
| `MONGODB_URI` | str | `"mongodb://localhost:27017"` | MongoDB connection string |
| `MONGODB_DB` | str | `"aimap"` | MongoDB database name |

---

## Database (`backend/app/database.py`)

Async MongoDB connection via **motor**. Provides:

- `get_database()` -- returns the motor database singleton
- `set_database(db)` -- override for testing (inject mongomock)
- `init_indexes()` -- creates all required indexes (idempotent)
- `close_client()` -- cleanly shuts down the connection

### Indexes

#### `endpoints` collection

| Index | Keys | Options | Purpose |
|-------|------|---------|---------|
| `ip_port_protocol_unique` | `{ip:1, port:1, protocol:1}` | unique | Dedup key -- one doc per (ip, port, protocol) |
| `risk_score_desc` | `{risk_score:-1}` | -- | Sort endpoints by severity |
| `protocol_auth` | `{protocol:1, auth_status:1}` | -- | Filter by protocol + auth combo |
| `geo_country` | `{geo.country_code:1}` | -- | Geo aggregation for maps |
| `tools_name` | `{tools.name:1}` | -- | Search by tool name |
| `range_id` | `{range_id:1}` | -- | Range monitoring page queries |
| `tags` | `{tags:1}` | -- | Tag-based filtering |
| `first_seen_desc` | `{first_seen:-1}` | -- | Recent discoveries feed |
| `text_search` | `{hostname, tools.name, tools.description, system_prompt}` | TEXT | Full-text search |

#### `analyses` collection

| Index | Keys | Options | Purpose |
|-------|------|---------|---------|
| `endpoint_id_unique` | `{endpoint_id:1}` | unique | 1:1 join to endpoints |
| `testing_status` | `{testing.status:1}` | -- | Filter tested/untested |

#### `scans` collection

| Index | Keys | Options | Purpose |
|-------|------|---------|---------|
| `status_created` | `{status:1, created_at:-1}` | -- | Active scans first |
| `created_by` | `{created_by:1}` | -- | User's scans |
| `config_range_id` | `{config.range_id:1}` | -- | Scans for a specific range |

#### `ranges` collection

| Index | Keys | Options | Purpose |
|-------|------|---------|---------|
| `cidr` | `{cidr:1}` | -- | Lookup by IP range |
| `ranges_created_by` | `{created_by:1}` | -- | User's ranges |
| `monitoring_next_scan` | `{monitoring.next_scan_at:1}` | -- | Scheduler pickup for recurring scans |

---

## Pydantic Models

All models use Pydantic v2. Located in `backend/app/models/`.

### `endpoint.py` -- AgentEndpoint

The core discovery record. One document per unique (ip, port, protocol).

**Main model: `AgentEndpoint`**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `id` | str (alias `_id`) | `""` | MongoDB document ID |
| `ip` | str | *required* | IP address |
| `port` | int (1-65535) | *required* | Port number |
| `hostname` | str | `""` | Resolved hostname |
| `url` | str | `""` | Full URL |
| `protocol` | ProtocolType | *required* | `mcp`, `openai_compat`, `langserve`, `autogen` |
| `framework` | str | `""` | Detected framework (e.g. `fastapi`) |
| `model` | str | `""` | Detected LLM model |
| `auth_status` | AuthStatus | `"unknown"` | `none`, `api_key`, `api_key_weak`, `oauth`, `basic`, `unknown` |
| `tools` | list[ToolInfo] | `[]` | Registered tools |
| `tool_count` | int | `0` | Number of tools |
| `dangerous_combos` | list[str] | `[]` | Dangerous tool combinations |
| `system_prompt` | str | `""` | Extracted system prompt |
| `system_prompt_extracted` | bool | `False` | Whether system prompt was extracted |
| `risk_score` | float (0-10) | `0.0` | Overall risk score |
| `risk_factors` | list[str] | `[]` | List of risk factor labels |
| `geo` | GeoInfo | default | Geographic/network location |
| `server` | ServerInfo | default | HTTP server metadata |
| `sources` | list[SourceRecord] | `[]` | Discovery provenance |
| `range_id` | str or None | `None` | Linked monitored range |
| `scan_ids` | list[str] | `[]` | Scans that found this endpoint |
| `analysis_id` | str or None | `None` | Linked analysis document |
| `first_seen` | datetime | now | First discovery timestamp |
| `last_seen` | datetime | now | Most recent observation |
| `created_at` | datetime | now | Document creation time |
| `updated_at` | datetime | now | Last update time |
| `tags` | list[str] | `[]` | User-defined labels |

**Nested models:**

- `ToolInfo` -- name, description, parameters, risk level, risk reason
- `GeoInfo` -- country, country_code, region, city, lat, lon, asn, org
- `ServerInfo` -- banner, headers, tls, cors_open
- `SourceRecord` -- source name, scan_id, template, discovered_at, raw_data

**DTOs:**

- `AgentEndpointCreate` -- all fields for inserting a new endpoint
- `AgentEndpointUpdate` -- optional fields for partial updates

### `analysis.py` -- AgentAnalysis

Deep-dive record linked 1:1 from an endpoint. Contains fingerprint, scan records, and exploitation results.

**Main model: `AgentAnalysis`**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `id` | str (alias `_id`) | `""` | MongoDB document ID |
| `endpoint_id` | str | `""` | Linked endpoint |
| `fingerprint` | Fingerprint | default | Protocol-level fingerprint |
| `active_scans` | list[ScanRecord] | `[]` | Scan run records |
| `testing` | TestingInfo | default | Exploitation test data |
| `created_at` | datetime | now | Document creation time |
| `updated_at` | datetime | now | Last update time |
| `analyzed_by` | str | `""` | User who performed analysis |
| `tags` | list[str] | `[]` | Labels |

**Nested models:**

- `Fingerprint` -- protocol_version, capabilities, tool_details, system_prompt_full, model_detected, model_detection_method, permission_model, rate_limiting, input_validation
- `ToolDetail` -- extended tool info with injectable, tested, injection_vector fields
- `ScanRecord` -- scan_id, scan_type, status, templates_run, findings, raw_output
- `Finding` -- template, severity, title, detail, evidence
- `TestingInfo` -- status, last_tested_at, attack_surface, attack_graph, test_results, exploitation_log
- `TestResult` -- test_id, category, technique, payload, response, success, severity, chain
- `ExploitationStep` -- step number, reasoning, action, result, timestamp
- `AttackGraph` -- nodes and edges for attack chain visualization
- `AttackNode` -- id, type (entry_point/technique/tool/impact), label
- `AttackEdge` -- from/to node IDs (aliased as from_node/to_node in Python)

### `scan.py` -- Scan

Tracks scan jobs (active scanning and 3P ingestion runs).

**Main model: `Scan`**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `id` | str (alias `_id`) | `""` | MongoDB document ID |
| `name` | str | `""` | Human-readable scan name |
| `type` | ScanType | `"active"` | `active` or `ingestion` |
| `status` | ScanStatus | `"queued"` | `queued`, `running`, `completed`, `failed`, `cancelled` |
| `config` | ScanConfig | default | Scan configuration |
| `progress` | ScanProgress | default | Live progress tracking |
| `results_summary` | ResultsSummary | default | Post-scan summary |
| `endpoint_ids` | list[str] | `[]` | Discovered endpoint IDs |
| `created_by` | str | `""` | User who created the scan |
| `created_at` | datetime | now | Creation time |
| `updated_at` | datetime | now | Last update time |

**Nested models:**

- `ScanConfig` -- target CIDR, range_id, protocols, templates, ports, rate_limit, timeout_ms; for ingestion: source, query, max_results
- `ScanProgress` -- total_hosts, scanned, alive, agents_found, percent_complete, current_ip, started_at, estimated_completion
- `ResultsSummary` -- total_endpoints, by_protocol dict, by_risk dict, no_auth_count

**DTOs:**

- `ScanCreate` -- name, type, config, created_by

### `range.py` -- MonitoredRange

Monitored IP ranges with recurring scan scheduling and aggregated stats.

**Main model: `MonitoredRange`**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `id` | str (alias `_id`) | `""` | MongoDB document ID |
| `name` | str | `""` | Human-readable name |
| `cidr` | str | `""` | IP range in CIDR notation |
| `total_hosts` | int | `0` | Number of hosts in range |
| `monitoring` | MonitoringConfig | default | Scheduling config |
| `stats` | RangeStats | default | Aggregated statistics |
| `scan_ids` | list[str] | `[]` | Historical scan IDs |
| `created_by` | str | `""` | User who created the range |
| `created_at` | datetime | now | Creation time |
| `updated_at` | datetime | now | Last update time |
| `tags` | list[str] | `[]` | Labels |

**Nested models:**

- `MonitoringConfig` -- enabled, interval_hours (min 1), last_scan_id, last_scanned_at, next_scan_at
- `RangeStats` -- total_endpoints, by_protocol, by_risk, no_auth_count, trend
- `Trend` -- endpoints_7d_ago, endpoints_30d_ago, direction (`increasing`/`decreasing`/`stable`)

**DTOs:**

- `RangeCreate` -- name, cidr, total_hosts, monitoring, created_by, tags
