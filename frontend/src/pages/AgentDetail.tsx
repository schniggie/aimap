import { Link, useParams } from "react-router-dom";
import {
  ArrowLeft,
  Swords,
  Shield,
  AlertTriangle,
  Globe,
  Server,
  Lock,
  ExternalLink,
  FileText,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { mockEndpoints, mockAnalysis } from "@/lib/mock-data";
import { useEndpointById, useAnalysis } from "@/hooks/useApi";
import type { RiskLevel } from "@/types";

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

export function AgentDetail() {
  const { id } = useParams<{ id: string }>();

  // API calls
  const { data: apiEndpoint } = useEndpointById(id);
  const { data: apiAnalysis } = useAnalysis(id);

  // Fallback to mock data
  const endpoint = apiEndpoint ?? mockEndpoints.find((ep) => ep.id === id) ?? mockEndpoints[0];
  const analysis = apiAnalysis ?? (endpoint.id === "ep_001" ? mockAnalysis : null);

  return (
    <div className="px-6 py-6 space-y-6">
      {/* Back link */}
      <Link
        to="/explore"
        className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground transition-colors"
      >
        <ArrowLeft className="h-4 w-4" />
        Back to results
      </Link>

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4 flex-wrap">
          <h1 className="text-2xl font-mono font-bold text-white">
            {endpoint.ip}:{endpoint.port}
          </h1>
          <Badge variant={endpoint.risk_score > 0 ? riskBadgeVariant(endpoint.risk_score) : "secondary"} className="text-sm">
            {endpoint.risk_score > 0 ? `${riskLabel(endpoint.risk_score)} ${endpoint.risk_score}` : "Risk N/A"}
          </Badge>
          <Badge variant="info">
            {endpoint.protocol === "openai_compat" ? "OpenAI" : endpoint.protocol.toUpperCase()}
          </Badge>
          <Badge variant={endpoint.auth_status === "none" ? "destructive" : endpoint.auth_status === "unknown" ? "secondary" : "outline"}>
            {endpoint.auth_status === "none"
              ? "No Auth"
              : endpoint.auth_status === "api_key"
              ? "API Key"
              : endpoint.auth_status === "unknown"
              ? "Auth N/A"
              : endpoint.auth_status}
          </Badge>
        </div>
        <div className="flex gap-2">
          {analysis?.testing?.test_results?.length ? (
            <Link to={`/agent/${endpoint.id}/results`}>
              <Button variant="outline" className="gap-2">
                <FileText className="h-4 w-4" />
                View Results
              </Button>
            </Link>
          ) : null}
          <Link to={`/agent/${endpoint.id}/test`}>
            <Button variant="destructive" className="gap-2">
              <Swords className="h-4 w-4" />
              Attack
            </Button>
          </Link>
        </div>
      </div>

      {/* Server Info */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-2">
            <Server className="h-4 w-4" />
            Server
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-x-8 gap-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-muted-foreground">Hostname</span>
              <span className="font-mono">{endpoint.hostname || "\u2014"}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Framework</span>
              <span className="font-mono">
                {endpoint.framework || "N/A"}
                {endpoint.server?.banner ? ` (${endpoint.server.banner})` : ""}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">TLS</span>
              <span>{endpoint.server.tls ? "Yes" : "No"}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">CORS</span>
              <span>{endpoint.server.cors_open ? "Open (*)" : "Restricted"}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Location</span>
              <span>
                {endpoint.geo?.city || "N/A"}, {endpoint.geo?.region || "N/A"}, {endpoint.geo?.country_code || "N/A"} · {endpoint.geo?.asn || "N/A"} ({endpoint.geo?.org || "N/A"})
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Model</span>
              <span className="font-mono">{endpoint.model || "N/A"}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">First seen</span>
              <span>{new Date(endpoint.first_seen).toLocaleDateString()}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Last seen</span>
              <span>{new Date(endpoint.last_seen).toLocaleDateString()}</span>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Tools */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-2">
            <Shield className="h-4 w-4" />
            Tools ({endpoint.tool_count > 0 ? endpoint.tool_count : "N/A"})
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-0">
          {endpoint.tools.length === 0 && !analysis?.fingerprint?.tool_details?.length ? (
            <p className="text-sm text-muted-foreground italic py-4">
              Tools not yet enumerated — run an active scan to discover tools.
            </p>
          ) : (
            (analysis?.fingerprint?.tool_details || endpoint.tools.map((t) => ({
              ...t,
              input_schema: {},
              injectable: false,
              tested: false,
            }))).map((tool, idx) => (
              <div key={tool.name}>
                {idx > 0 && <Separator className="my-2" />}
                <div className="py-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      {(tool.risk === "critical" || tool.risk === "high") && (
                        <AlertTriangle className="h-4 w-4 text-severity-critical" />
                      )}
                      <span className="font-mono font-semibold text-sm">{tool.name}</span>
                    </div>
                    <Badge variant={tool.risk}>{tool.risk.toUpperCase()}</Badge>
                  </div>
                  <p className="text-sm text-muted-foreground mt-1">{tool.description}</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    Risk: {tool.risk_reason}
                  </p>
                  <p className="text-xs mt-1">
                    <span className="text-muted-foreground">Injectable: </span>
                    <span className={tool.injectable ? "text-severity-critical" : "text-severity-low"}>
                      {tool.injectable ? "Yes" : "No"}
                    </span>
                    <span className="text-muted-foreground"> · Tested: </span>
                    <span>{tool.tested ? "Yes" : "No"}</span>
                    {'injection_vector' in tool && tool.injection_vector && (
                      <>
                        <span className="text-muted-foreground"> · Vector: </span>
                        <span className="text-severity-high">{tool.injection_vector as string}</span>
                      </>
                    )}
                  </p>
                </div>
              </div>
            ))
          )}
        </CardContent>
      </Card>

      {/* Dangerous combos */}
      {endpoint.dangerous_combos?.length > 0 ? (
        <Card className="border-severity-critical/30 bg-severity-critical/5">
          <CardContent className="p-4 flex items-start gap-3">
            <AlertTriangle className="h-5 w-5 text-severity-critical shrink-0 mt-0.5" />
            <div>
              <p className="text-sm font-semibold text-severity-critical">Dangerous Combinations Detected</p>
              {endpoint.dangerous_combos.map((combo) => (
                <p key={combo} className="text-sm font-mono mt-1">{combo}</p>
              ))}
            </div>
          </CardContent>
        </Card>
      ) : null}

      {/* System Prompt */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-2">
            <Lock className="h-4 w-4" />
            System Prompt
          </CardTitle>
        </CardHeader>
        <CardContent>
          {endpoint.system_prompt_extracted && endpoint.system_prompt ? (
            <ScrollArea maxHeight="200px">
              <pre className="font-mono text-sm text-foreground whitespace-pre-wrap bg-secondary/50 p-4 border">
                {analysis?.fingerprint?.system_prompt_full || endpoint.system_prompt}
              </pre>
            </ScrollArea>
          ) : (
            <p className="text-sm text-muted-foreground italic">
              N/A — run a prompt extraction scan to attempt extraction
            </p>
          )}
        </CardContent>
      </Card>

      {/* Risk Factors */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider">
            Risk Factors
          </CardTitle>
        </CardHeader>
        <CardContent>
          {endpoint.risk_factors?.length > 0 ? (
            <div className="flex flex-wrap gap-2">
              {endpoint.risk_factors.map((factor) => (
                <Badge key={factor} variant="destructive" className="font-mono text-xs">
                  {factor}
                </Badge>
              ))}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground italic">N/A — not yet analyzed</p>
          )}
        </CardContent>
      </Card>

      {/* Sources */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-2">
            <ExternalLink className="h-4 w-4" />
            Sources
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-4">
            {endpoint.sources.map((src, idx) => (
              <div key={idx} className="text-sm">
                <span className="font-medium capitalize">{src.source}</span>
                <span className="text-muted-foreground">
                  {" "}({new Date(src.discovered_at).toLocaleDateString()})
                </span>
                {src.scan_id && (
                  <span className="text-muted-foreground font-mono text-xs ml-1">
                    {src.scan_id}
                  </span>
                )}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Attack Graph placeholder */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider">
            Attack Graph
          </CardTitle>
        </CardHeader>
        <CardContent>
          {analysis?.testing?.attack_graph?.nodes?.length ? (
            <div className="bg-secondary/30 border p-6">
              <div className="flex items-center justify-center gap-2 flex-wrap">
                {analysis.testing!.attack_graph.nodes.map((node, idx) => (
                  <div key={node.id} className="flex items-center gap-2">
                    <div
                      className={`px-3 py-2 border text-xs font-mono ${
                        node.type === "entry_point"
                          ? "border-severity-info bg-severity-info/10 text-severity-info"
                          : node.type === "technique"
                          ? "border-severity-high bg-severity-high/10 text-severity-high"
                          : node.type === "tool"
                          ? "border-severity-critical bg-severity-critical/10 text-severity-critical"
                          : "border-severity-critical bg-severity-critical/20 text-severity-critical font-bold"
                      }`}
                    >
                      {node.label}
                      {node.success !== undefined && (
                        <span className="ml-1">{node.success ? " [OK]" : " [FAIL]"}</span>
                      )}
                    </div>
                    {idx < analysis.testing!.attack_graph.nodes.length - 1 && (
                      <span className="text-muted-foreground">&#8594;</span>
                    )}
                  </div>
                ))}
              </div>
              <p className="text-xs text-muted-foreground text-center mt-4">
                Interactive DAG visualization -- Coming Soon
              </p>
            </div>
          ) : (
            <div className="flex items-center justify-center h-32 bg-secondary/20 border-dashed border">
              <p className="text-sm text-muted-foreground">
                Attack Graph -- Coming Soon
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Scan History */}
      {(analysis?.active_scans?.length ?? 0) > 0 && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-2">
              <Globe className="h-4 w-4" />
              Scan History
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {analysis!.active_scans.map((scan) => (
              <div
                key={scan.scan_id}
                className="flex items-center justify-between py-2 text-sm"
              >
                <div className="flex items-center gap-3">
                  <span className="font-mono text-xs">{scan.scan_id}</span>
                  <Badge variant="secondary" className="text-[10px]">{scan.scan_type}</Badge>
                  <span className="text-muted-foreground">
                    {new Date(scan.started_at).toLocaleDateString()}
                  </span>
                </div>
                <span className="text-muted-foreground text-xs">
                  {scan.findings.length} finding{scan.findings.length !== 1 ? "s" : ""}
                </span>
              </div>
            ))}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
