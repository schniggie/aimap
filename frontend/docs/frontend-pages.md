# AIMap Frontend Documentation

## Pages & Routes

| Route | Component | File | Description |
|-------|-----------|------|-------------|
| `/` | Landing | `src/pages/Landing.tsx` | Homepage with stat cards, search bar, recent discoveries, protocol breakdown chart, map placeholder |
| `/search` | SearchPage | `src/pages/Search.tsx` | Google-style search results with filtering, pagination |
| `/explore` | Explore | `src/pages/Explore.tsx` | Browse/filter all agents with data table, facets, map placeholder |
| `/agent/:id` | AgentDetail | `src/pages/AgentDetail.tsx` | Full agent profile: server info, tools, system prompt, risk factors, attack graph, scan history |
| `/agent/:id/test` | TestAgent | `src/pages/TestAgent.tsx` | Launch red-team attack with configuration and live streaming log |
| `/agent/:id/test/:testId` | TestInfo | `src/pages/TestInfo.tsx` | Post-attack report: summary stats, attack graph, findings, exploitation log |
| `/scans` | Scans | `src/pages/Scans.tsx` | Manage scan jobs: active scans with progress, completed scans table, new scan dialog |
| `/ranges` | Ranges | `src/pages/Ranges.tsx` | IP range monitoring: range cards with stats, trends, monitoring config, action buttons |

## Mock Data Usage

| Page | Mock Data Source |
|------|-----------------|
| Landing | `mockStats`, `mockEndpoints` (first 5 for recent discoveries) |
| Search | `mockEndpoints` (filtered by query string) |
| Explore | `mockEndpoints` (with filters applied) |
| AgentDetail | `mockEndpoints` (lookup by ID), `mockAnalysis` (for ep_001) |
| TestAgent | `mockEndpoints` (target info), `mockAttackLog` (simulated streaming) |
| TestInfo | `mockEndpoints` (target info), `mockAnalysis.testing` (results) |
| Scans | `mockScans` (active + completed) |
| Ranges | `mockRanges` |

Mock data file: `src/lib/mock-data.ts`
- 13 mock endpoints with varied protocols (MCP, LangServe, OpenAI, AutoGen), risk levels, geographies
- 3 mock scans (1 running, 2 completed)
- 2 mock ranges (Production AWS, Staging GCP)
- 1 mock analysis with full fingerprint, attack graph, test results, and exploitation log
- 12 mock attack log entries for streaming simulation

## Component Library

All components are in `src/components/ui/` and follow shadcn/ui patterns.

| Component | File | Exports |
|-----------|------|---------|
| Button | `button.tsx` | `Button`, `buttonVariants` -- variants: default, destructive, outline, secondary, ghost, link; sizes: sm, default, lg, icon |
| Card | `card.tsx` | `Card`, `CardHeader`, `CardTitle`, `CardDescription`, `CardContent`, `CardFooter` |
| Input | `input.tsx` | `Input` -- styled text input |
| Badge | `badge.tsx` | `Badge`, `badgeVariants` -- variants: default, secondary, destructive, outline, critical, high, medium, low, info |
| Table | `table.tsx` | `Table`, `TableHeader`, `TableBody`, `TableFooter`, `TableRow`, `TableHead`, `TableCell`, `TableCaption` |
| Select | `select.tsx` | `Select` -- native select with custom styling and chevron |
| Dialog | `dialog.tsx` | `Dialog`, `DialogTrigger`, `DialogContent`, `DialogHeader`, `DialogTitle`, `DialogDescription`, `DialogFooter` -- uses React portals |
| Progress | `progress.tsx` | `Progress` -- progress bar with value/max props |
| Separator | `separator.tsx` | `Separator` -- horizontal/vertical divider |
| ScrollArea | `scroll-area.tsx` | `ScrollArea` -- scrollable container with maxHeight |
| Pagination | `pagination.tsx` | `Pagination` -- page numbers with prev/next, ellipsis for large ranges |

### Layout Components

| Component | File | Description |
|-----------|------|-------------|
| Navbar | `src/components/layout/Navbar.tsx` | Fixed top bar: logo, search, nav links (Explore, Scans, Ranges) |
| Layout | `src/components/layout/Layout.tsx` | Wraps pages with Navbar + main content area via React Router Outlet |

## Design System

### Colors

| Token | Value | Usage |
|-------|-------|-------|
| Background | `hsl(0 0% 3.9%)` | Page background (near-black) |
| Card | `hsl(0 0% 6%)` | Card backgrounds |
| Border | `hsl(0 0% 18%)` | All borders |
| Foreground | `hsl(0 0% 98%)` | Primary text (near-white) |
| Muted Foreground | `hsl(0 0% 63.9%)` | Secondary text |
| Primary | `hsl(210 100% 52%)` | Interactive elements (blue) |
| Destructive | `hsl(0 84.2% 60.2%)` | Danger actions |

### Severity Colors

| Level | Color | Hex |
|-------|-------|-----|
| Critical | Red | `#ef4444` |
| High | Orange | `#f97316` |
| Medium | Yellow | `#eab308` |
| Low | Green | `#22c55e` |
| Info | Blue | `#3b82f6` |

### Typography

- **UI text:** Inter (sans-serif)
- **Data/code:** JetBrains Mono (monospace) -- used for IPs, ports, scores, tool names, system prompts, code blocks
- Loaded via Google Fonts in `index.html`

### Spacing & Layout

- All border-radius: `0px` (sharp boxes everywhere, enforced via Tailwind config and CSS)
- Dark mode only (class `dark` on `<html>`)
- Dense, data-forward layout
- Page padding: `px-6 py-6`
- Card spacing: `space-y-6` between sections
- Grid layouts: `grid-cols-2`, `grid-cols-3` for stat cards and side-by-side sections

### Dependencies

| Package | Purpose |
|---------|---------|
| React 19 + Vite 8 | Framework + build |
| react-router-dom 6 | Client-side routing |
| @tanstack/react-query 5 | Data fetching (configured, not yet wired) |
| recharts 3 | Charts (protocol breakdown bar chart) |
| lucide-react | Icons |
| class-variance-authority | Component variant management |
| clsx + tailwind-merge | Class name utilities |
| tailwindcss 3 + tailwindcss-animate | Styling |

## API Client

File: `src/lib/api.ts`

Provides fetch-based functions for all backend endpoints. Currently not wired to pages (pages use mock data). Functions:

- `getEndpoints(params)` -- paginated endpoint listing with filters
- `getEndpointById(id)` -- single endpoint
- `searchEndpoints(query, page, per_page)` -- text search
- `getStats()` -- dashboard statistics
- `getGeoData()` -- geo aggregations
- `getAnalysis(endpointId)` -- agent analysis
- `getScans(params)` -- paginated scan listing
- `getScanById(id)` -- single scan
- `createScan(config)` -- create new scan
- `pauseScan(id)` / `stopScan(id)` -- scan control
- `getRanges()` -- all ranges
- `getRangeById(id)` -- single range
- `createRange(data)` -- create new range
- `deleteRange(id)` -- delete range
- `startAttack(endpointId, config)` -- launch attack

## TypeScript Types

File: `src/types/index.ts`

Matches backend MongoDB schemas:
- `AgentEndpoint` -- core discovery record
- `ToolInfo`, `GeoInfo`, `ServerInfo`, `SourceRecord` -- sub-documents
- `AgentAnalysis`, `Fingerprint`, `ToolDetail`, `TestingInfo`, `TestResult`, `AttackGraph`, `AttackNode`, `AttackEdge` -- analysis records
- `Scan`, `ScanConfig`, `ScanProgress`, `ResultsSummary` -- scan job types
- `MonitoredRange`, `MonitoringConfig`, `RangeStats` -- range monitoring types
- `PaginatedResponse<T>`, `StatsResponse`, `GeoAggregation` -- API response types
- `AttackLogEntry` -- live attack log streaming type
