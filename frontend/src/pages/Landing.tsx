import { useState, useMemo } from "react";
import { useNavigate, Link } from "react-router-dom";
import { Search, AlertTriangle, ShieldOff, Globe } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { useStats, useEndpoints, useGlobeData } from "@/hooks/useApi";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";
import { GlobeVisualization, GlobeLegend } from "@/components/GlobeVisualization";
import type { RiskLevel } from "@/types";

const protocolColors: Record<string, string> = {
  MCP: "#3b82f6",
  OpenAI: "#8b5cf6",
  LangServe: "#06b6d4",
  AutoGen: "#f59e0b",
};

function protocolDisplayName(key: string): string {
  switch (key) {
    case "openai_compat": return "OpenAI";
    case "langserve": return "LangServe";
    case "autogen": return "AutoGen";
    case "mcp": return "MCP";
    default: return key;
  }
}

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

export function Landing() {
  const [query, setQuery] = useState("");
  const navigate = useNavigate();

  // Fetch from API
  const { data: apiStats } = useStats();
  const { data: recentData } = useEndpoints({ page: 1, page_size: 5, sort_by: "-first_seen" });
  const { data: globePoints } = useGlobeData();

  const totalEndpoints = apiStats?.total ?? 0;
  const criticalCount = apiStats?.by_risk?.critical ?? null;
  const noAuthPercent = apiStats && apiStats.no_auth_count > 0 && apiStats.total > 0
    ? ((apiStats.no_auth_count / apiStats.total) * 100).toFixed(1)
    : null;

  const byProtocol = apiStats?.by_protocol ?? {};

  const protocolTotal = Object.values(byProtocol).reduce((a, b) => a + b, 0);
  const protocolData = useMemo(
    () =>
      Object.entries(byProtocol).map(([name, value]) => ({
        name: protocolDisplayName(name),
        value,
        percent: protocolTotal > 0 ? ((value / protocolTotal) * 100).toFixed(1) : "0",
      })),
    [byProtocol, protocolTotal]
  );

  const recent = recentData?.items ?? [];

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (query.trim()) {
      navigate(`/search?q=${encodeURIComponent(query.trim())}`);
    }
  };

  return (
    <div className="px-6 py-6 space-y-8">
      {/* Stat cards */}
      <div className="grid grid-cols-3 gap-4">
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Agents Discovered</p>
                <p className="text-3xl font-mono font-bold text-white">
                  {Number(totalEndpoints).toLocaleString()}
                </p>
              </div>
              <Globe className="h-8 w-8 text-severity-info opacity-60" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Critical Risk</p>
                <p className="text-3xl font-mono font-bold text-severity-critical">
                  {criticalCount != null ? Number(criticalCount).toLocaleString() : "N/A"}
                </p>
              </div>
              <AlertTriangle className="h-8 w-8 text-severity-critical opacity-60" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">No Auth</p>
                <p className="text-3xl font-mono font-bold text-severity-high">
                  {noAuthPercent != null ? `${noAuthPercent}%` : "N/A"}
                </p>
              </div>
              <ShieldOff className="h-8 w-8 text-severity-high opacity-60" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Search bar */}
      <div className="flex justify-center">
        <form onSubmit={handleSearch} className="w-full max-w-2xl">
          <div className="relative">
            <Search className="absolute left-4 top-1/2 -translate-y-1/2 h-5 w-5 text-muted-foreground" />
            <Input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search agents, IPs, tools, protocols..."
              className="pl-12 h-12 text-base bg-secondary/50 border-border"
            />
          </div>
          <p className="text-xs text-muted-foreground mt-2 text-center">
            Try: <span className="font-mono">protocol:mcp auth:none</span> or{" "}
            <span className="font-mono">tool:query_db</span> or{" "}
            <span className="font-mono">country:US risk:critical</span>
          </p>
        </form>
      </div>

      {/* Two-column section */}
      <div className="grid grid-cols-2 gap-6">
        {/* Recent Discoveries */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider">
              Recent Discoveries
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-1 pt-0">
            {recent.length === 0 && (
              <p className="text-sm text-muted-foreground italic py-4 px-3">
                No endpoints discovered yet. Run a scan to populate this list.
              </p>
            )}
            {recent.map((ep) => (
              <Link
                key={ep.id}
                to={`/agent/${ep.id}`}
                className="flex items-center justify-between py-2 px-3 hover:bg-secondary/50 transition-colors"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <span className="font-mono text-sm text-white">
                    {ep.ip}:{ep.port}
                  </span>
                  <Badge variant={ep.protocol === "mcp" ? "info" : ep.protocol === "langserve" ? "medium" : "secondary"} className="text-[10px]">
                    {ep.protocol === "openai_compat" ? "OpenAI" : ep.protocol.toUpperCase()}
                  </Badge>
                  <Badge variant={ep.risk_score > 0 ? riskBadgeVariant(ep.risk_score) : "secondary"} className="text-[10px]">
                    {ep.risk_score > 0 ? riskBadgeVariant(ep.risk_score).toUpperCase() : "N/A"}
                  </Badge>
                </div>
                <span className="text-xs text-muted-foreground shrink-0">
                  {timeAgo(ep.first_seen)}
                </span>
              </Link>
            ))}
          </CardContent>
        </Card>

        {/* Protocol Breakdown */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider">
              Protocol Breakdown
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-0">
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={protocolData} layout="vertical" margin={{ left: 0, right: 20 }}>
                <XAxis type="number" hide />
                <YAxis
                  type="category"
                  dataKey="name"
                  width={80}
                  tick={{ fill: "#9ca3af", fontSize: 12 }}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip
                  cursor={false}
                  contentStyle={{
                    backgroundColor: "hsl(0 0% 6%)",
                    border: "1px solid hsl(0 0% 18%)",
                    borderRadius: 0,
                    fontSize: 12,
                  }}
                  // eslint-disable-next-line @typescript-eslint/no-explicit-any
                  formatter={(value: any, _name: any, entry: any) => [
                    `${Number(value).toLocaleString()} (${entry?.payload?.percent ?? ""}%)`,
                    "Count",
                  ]}
                />
                <Bar dataKey="value" barSize={24}>
                  {protocolData.map((entry) => (
                    <Cell
                      key={entry.name}
                      fill={protocolColors[entry.name] || "#3b82f6"}
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      {/* 3D Globe */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-2">
            <Globe className="h-4 w-4" />
            Global Threat Map
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {globePoints && globePoints.length > 0 ? (
            <>
              <GlobeVisualization points={globePoints} height={500} />
              <div className="p-3 border-t border-border">
                <GlobeLegend points={globePoints} />
              </div>
            </>
          ) : (
            <div className="flex items-center justify-center h-64 bg-secondary/20">
              <div className="text-center">
                <Globe className="h-12 w-12 text-muted-foreground/30 mx-auto mb-2 animate-pulse" />
                <p className="text-sm text-muted-foreground">Loading globe data...</p>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
