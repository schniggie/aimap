import { useState, useEffect } from "react";
import { useSearchParams, Link, useNavigate } from "react-router-dom";
import { Search as SearchIcon } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Pagination } from "@/components/ui/pagination";
import { mockEndpoints } from "@/lib/mock-data";
import { useSearchEndpoints } from "@/hooks/useApi";
import type { AgentEndpoint, RiskLevel } from "@/types";

function riskBadgeVariant(score: number): RiskLevel {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 5) return "medium";
  if (score >= 3) return "low";
  return "info";
}

function riskLabel(score: number): string {
  if (score >= 9) return "CRITICAL";
  if (score >= 7) return "HIGH";
  if (score >= 5) return "MEDIUM";
  if (score >= 3) return "LOW";
  return "INFO";
}

function authLabel(auth: string): string {
  switch (auth) {
    case "none": return "No Auth";
    case "api_key": return "API Key";
    case "oauth": return "OAuth";
    case "basic": return "Basic Auth";
    default: return auth;
  }
}

const PER_PAGE = 10;

export function SearchPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const initialQuery = searchParams.get("q") || "";
  const [query, setQuery] = useState(initialQuery);
  const [currentPage, setCurrentPage] = useState(1);

  // Reset page when the URL query param changes
  useEffect(() => {
    setQuery(initialQuery);
    setCurrentPage(1);
  }, [initialQuery]);

  // API call
  const { data: searchData } = useSearchEndpoints(initialQuery, currentPage, PER_PAGE);

  // Mock-based fallback filtering
  const mockFiltered = mockEndpoints.filter((ep) => {
    if (!initialQuery) return true;
    const q = initialQuery.toLowerCase();
    const searchable = `${ep.ip} ${ep.port} ${ep.hostname} ${ep.protocol} ${ep.auth_status} ${ep.tools.map((t) => t.name).join(" ")} ${ep.system_prompt} ${ep.geo.country} ${ep.geo.org} ${ep.tags.join(" ")}`.toLowerCase();
    return searchable.includes(q);
  });

  // Decide data source
  const useApi = !!(searchData?.items && searchData.items.length > 0);
  const results: AgentEndpoint[] = useApi
    ? searchData!.items
    : mockFiltered.slice((currentPage - 1) * PER_PAGE, currentPage * PER_PAGE);
  const totalResults = useApi ? searchData!.total : mockFiltered.length;
  const totalPages = Math.ceil(totalResults / PER_PAGE);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (query.trim()) {
      navigate(`/search?q=${encodeURIComponent(query.trim())}`);
      setCurrentPage(1);
    }
  };

  return (
    <div className="px-6 py-6 space-y-6">
      {/* Search bar */}
      <form onSubmit={handleSearch}>
        <div className="relative max-w-2xl">
          <SearchIcon className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search agents, IPs, tools, protocols..."
            className="pl-9 h-10 bg-secondary/50"
          />
        </div>
      </form>

      {/* Result count */}
      <p className="text-sm text-muted-foreground">
        About <span className="text-foreground font-medium">{totalResults}</span> results
        {initialQuery && (
          <span>
            {" "}for <span className="font-mono text-foreground">"{initialQuery}"</span>
          </span>
        )}{" "}
        (0.24s)
      </p>

      {/* Results */}
      <div className="space-y-3">
        {results.map((ep) => (
          <Link key={ep.id} to={`/agent/${ep.id}`} className="block">
            <Card className="hover:border-primary/50 transition-colors">
              <CardContent className="p-4">
                <div className="flex items-start justify-between">
                  <div className="space-y-2 min-w-0 flex-1">
                    {/* Header row */}
                    <div className="flex items-center gap-3 flex-wrap">
                      <span className="font-mono font-semibold text-white">
                        {ep.ip}:{ep.port}
                      </span>
                      <Badge
                        variant={
                          ep.protocol === "mcp"
                            ? "info"
                            : ep.protocol === "langserve"
                            ? "medium"
                            : "secondary"
                        }
                      >
                        {ep.protocol === "openai_compat" ? "OpenAI" : ep.protocol === "langserve" ? "LangServe" : ep.protocol === "autogen" ? "AutoGen" : "MCP"}
                      </Badge>
                      <Badge variant={ep.auth_status === "none" ? "destructive" : ep.auth_status === "unknown" ? "secondary" : "secondary"}>
                        {ep.auth_status === "unknown" ? "Auth N/A" : authLabel(ep.auth_status)}
                      </Badge>
                      <Badge variant={ep.risk_score > 0 ? riskBadgeVariant(ep.risk_score) : "secondary"}>
                        {ep.risk_score > 0 ? `${riskLabel(ep.risk_score)} (${ep.risk_score})` : "Risk N/A"}
                      </Badge>
                    </div>

                    {/* Framework */}
                    <p className="text-sm text-muted-foreground">
                      {ep.protocol === "openai_compat" ? "OpenAI Compatible" : ep.protocol.toUpperCase()} Server
                      {ep.framework ? ` · ${ep.framework}` : ""}
                      {ep.auth_status === "none" ? " · No Auth" : ""}
                    </p>

                    {/* Tools */}
                    <p className="text-sm">
                      <span className="text-muted-foreground">Tools: </span>
                      {ep.tools.length > 0 ? (
                        <>
                          <span className="font-mono text-foreground">
                            {ep.tools.map((t) => t.name).join(", ")}
                          </span>
                          <span className="text-muted-foreground"> ({ep.tool_count} total)</span>
                        </>
                      ) : (
                        <span className="text-muted-foreground italic">N/A — not yet enumerated</span>
                      )}
                    </p>

                    {/* System prompt snippet */}
                    {ep.system_prompt_extracted && ep.system_prompt ? (
                      <p className="text-xs text-muted-foreground font-mono truncate max-w-xl">
                        "{ep.system_prompt.slice(0, 100)}
                        {ep.system_prompt.length > 100 ? "..." : ""}"
                      </p>
                    ) : (
                      <p className="text-xs text-muted-foreground italic">
                        System prompt — N/A
                      </p>
                    )}

                    {/* Meta */}
                    <p className="text-xs text-muted-foreground">
                      First seen: {new Date(ep.first_seen).toLocaleDateString()} ·{" "}
                      {ep.geo?.city || "N/A"}, {ep.geo?.country_code || "N/A"} · {ep.geo?.org || "N/A"}
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </Link>
        ))}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <Pagination
          currentPage={currentPage}
          totalPages={totalPages}
          onPageChange={setCurrentPage}
        />
      )}
    </div>
  );
}
