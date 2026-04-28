import { useState, useMemo } from "react";
import { Link } from "react-router-dom";
import { Globe } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Select } from "@/components/ui/select";
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table";
import { Pagination } from "@/components/ui/pagination";
import { Separator } from "@/components/ui/separator";
import { mockEndpoints } from "@/lib/mock-data";
import { useEndpoints, useGlobeData } from "@/hooks/useApi";
import { GlobeVisualization, GlobeLegend } from "@/components/GlobeVisualization";
import type { AgentEndpoint, RiskLevel } from "@/types";

function riskBadgeVariant(score: number): RiskLevel {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 5) return "medium";
  if (score >= 3) return "low";
  return "info";
}

function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function protocolLabel(p: string): string {
  switch (p) {
    case "openai_compat": return "OpenAI";
    case "langserve": return "LangServe";
    case "autogen": return "AutoGen";
    default: return "MCP";
  }
}

// Facet computation
function computeFacets(endpoints: AgentEndpoint[]) {
  const tools: Record<string, number> = {};
  const orgs: Record<string, number> = {};
  const countries: Record<string, number> = {};
  for (const ep of endpoints) {
    for (const t of ep.tools) {
      tools[t.name] = (tools[t.name] || 0) + 1;
    }
    if (ep.geo?.org) orgs[ep.geo.org] = (orgs[ep.geo.org] || 0) + 1;
    if (ep.geo?.country_code) countries[ep.geo.country_code] = (countries[ep.geo.country_code] || 0) + 1;
  }
  const sort = (obj: Record<string, number>) =>
    Object.entries(obj)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);
  return {
    topTools: sort(tools),
    topOrgs: sort(orgs),
    topCountries: sort(countries),
  };
}

const PER_PAGE = 10;

export function Explore() {
  const [protocolFilter, setProtocolFilter] = useState("");
  const [riskFilter, setRiskFilter] = useState("");
  const [authFilter, setAuthFilter] = useState("");
  const [portFilter, setPortFilter] = useState("");
  const [countryFilter, setCountryFilter] = useState("");
  const [currentPage, setCurrentPage] = useState(1);

  // Build query params for the API
  const apiParams = useMemo(() => {
    const params: Parameters<typeof useEndpoints>[0] = {
      page: currentPage,
      page_size: PER_PAGE,
    };
    if (protocolFilter) params.protocol = protocolFilter;
    if (authFilter) params.auth_status = authFilter;
    if (countryFilter) params.country = countryFilter;
    // Map risk filter to risk_min/risk_max
    if (riskFilter) {
      switch (riskFilter) {
        case "critical": params.risk_min = 9.0; break;
        case "high": params.risk_min = 7.0; params.risk_max = 8.99; break;
        case "medium": params.risk_min = 4.0; params.risk_max = 6.99; break;
        case "low": params.risk_min = 1.0; params.risk_max = 3.99; break;
        case "info": params.risk_max = 0.99; break;
      }
    }
    return params;
  }, [protocolFilter, authFilter, countryFilter, riskFilter, currentPage]);

  const { data: apiData } = useEndpoints(apiParams);
  const { data: globePoints } = useGlobeData();

  // Mock-based fallback
  const mockFiltered = useMemo(() => {
    return mockEndpoints.filter((ep) => {
      if (protocolFilter && ep.protocol !== protocolFilter) return false;
      if (authFilter && ep.auth_status !== authFilter) return false;
      if (portFilter && String(ep.port) !== portFilter) return false;
      if (countryFilter && ep.geo.country_code !== countryFilter) return false;
      if (riskFilter) {
        const r = riskBadgeVariant(ep.risk_score);
        if (r !== riskFilter) return false;
      }
      return true;
    });
  }, [protocolFilter, authFilter, portFilter, countryFilter, riskFilter]);

  // Decide data source
  const useApi = !!(apiData?.items && apiData.items.length > 0);

  // If API has data, use it; otherwise use mock + client-side port filter
  let displayItems: AgentEndpoint[];
  let totalItems: number;

  if (useApi) {
    // Port filter is not a backend param, so apply client-side if needed
    const items = portFilter
      ? apiData!.items.filter((ep) => String(ep.port) === portFilter)
      : apiData!.items;
    displayItems = items;
    totalItems = portFilter ? items.length : apiData!.total;
  } else {
    displayItems = mockFiltered.slice((currentPage - 1) * PER_PAGE, currentPage * PER_PAGE);
    totalItems = mockFiltered.length;
  }

  const totalPages = Math.ceil(totalItems / PER_PAGE);
  const facets = computeFacets(useApi ? apiData!.items : mockFiltered);

  return (
    <div className="px-6 py-6 space-y-6">
      {/* 3D Globe */}
      {globePoints && globePoints.length > 0 && (
        <Card>
          <CardContent className="p-0">
            <GlobeVisualization points={globePoints} height={350} />
            <div className="p-2 border-t border-border">
              <GlobeLegend points={globePoints} />
            </div>
          </CardContent>
        </Card>
      )}

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <Select value={protocolFilter} onChange={(e) => { setProtocolFilter(e.target.value); setCurrentPage(1); }} className="w-36">
          <option value="">All Protocols</option>
          <option value="mcp">MCP</option>
          <option value="openai_compat">OpenAI</option>
          <option value="langserve">LangServe</option>
          <option value="autogen">AutoGen</option>
        </Select>
        <Select value={riskFilter} onChange={(e) => { setRiskFilter(e.target.value); setCurrentPage(1); }} className="w-32">
          <option value="">All Risk</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </Select>
        <Select value={authFilter} onChange={(e) => { setAuthFilter(e.target.value); setCurrentPage(1); }} className="w-32">
          <option value="">All Auth</option>
          <option value="none">No Auth</option>
          <option value="api_key">API Key</option>
          <option value="oauth">OAuth</option>
          <option value="basic">Basic</option>
        </Select>
        <Select value={portFilter} onChange={(e) => { setPortFilter(e.target.value); setCurrentPage(1); }} className="w-28">
          <option value="">All Ports</option>
          <option value="80">80</option>
          <option value="443">443</option>
          <option value="3000">3000</option>
          <option value="8000">8000</option>
          <option value="8080">8080</option>
          <option value="8443">8443</option>
          <option value="8888">8888</option>
        </Select>
        <Select value={countryFilter} onChange={(e) => { setCountryFilter(e.target.value); setCurrentPage(1); }} className="w-36">
          <option value="">All Countries</option>
          <option value="US">United States</option>
          <option value="DE">Germany</option>
          <option value="GB">United Kingdom</option>
          <option value="CN">China</option>
          <option value="JP">Japan</option>
          <option value="NL">Netherlands</option>
          <option value="IN">India</option>
        </Select>
      </div>

      {/* Data table */}
      <Card>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>IP:Port</TableHead>
              <TableHead>Protocol</TableHead>
              <TableHead>Auth</TableHead>
              <TableHead>Risk Score</TableHead>
              <TableHead>Tools</TableHead>
              <TableHead>Last Seen</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {displayItems.map((ep) => (
              <TableRow key={ep.id}>
                <TableCell>
                  <Link
                    to={`/agent/${ep.id}`}
                    className="font-mono text-sm text-primary hover:underline"
                  >
                    {ep.ip}:{ep.port}
                  </Link>
                </TableCell>
                <TableCell>
                  <Badge variant={ep.protocol === "mcp" ? "info" : "secondary"} className="text-[10px]">
                    {protocolLabel(ep.protocol)}
                  </Badge>
                </TableCell>
                <TableCell>
                  <Badge variant={ep.auth_status === "none" ? "destructive" : ep.auth_status === "unknown" ? "secondary" : "outline"} className="text-[10px]">
                    {ep.auth_status === "none" ? "None" : ep.auth_status === "api_key" ? "Key" : ep.auth_status === "unknown" ? "N/A" : ep.auth_status}
                  </Badge>
                </TableCell>
                <TableCell>
                  <Badge variant={ep.risk_score > 0 ? riskBadgeVariant(ep.risk_score) : "secondary"} className="font-mono text-[10px]">
                    {ep.risk_score > 0 ? ep.risk_score : "N/A"}
                  </Badge>
                </TableCell>
                <TableCell className="font-mono text-xs">{ep.tool_count > 0 ? ep.tool_count : "N/A"}</TableCell>
                <TableCell className="text-xs text-muted-foreground">
                  {timeAgo(ep.last_seen)}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Card>

      {/* Showing X of Y */}
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          Showing {((currentPage - 1) * PER_PAGE) + 1}
          -{Math.min(currentPage * PER_PAGE, totalItems)} of {totalItems}
        </p>
        {totalPages > 1 && (
          <Pagination
            currentPage={currentPage}
            totalPages={totalPages}
            onPageChange={setCurrentPage}
          />
        )}
      </div>

      {/* Facets */}
      <Separator />
      <div className="grid grid-cols-3 gap-6">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
              Top Tools
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-1">
            {facets.topTools.map(([name, count]) => (
              <div key={name} className="flex items-center justify-between py-1">
                <span className="font-mono text-sm">{name}</span>
                <span className="text-xs text-muted-foreground">({count})</span>
              </div>
            ))}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
              Top Orgs
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-1">
            {facets.topOrgs.map(([name, count]) => (
              <div key={name} className="flex items-center justify-between py-1">
                <span className="text-sm">{name}</span>
                <span className="text-xs text-muted-foreground">({count})</span>
              </div>
            ))}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
              Top Countries
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-1">
            {facets.topCountries.map(([name, count]) => (
              <div key={name} className="flex items-center justify-between py-1">
                <span className="text-sm font-mono">{name}</span>
                <span className="text-xs text-muted-foreground">({count})</span>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
