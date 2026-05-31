import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, Swords, Zap, FileText } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useEndpointById } from "@/hooks/useApi";
import { startAttack, streamAttackLogs } from "@/lib/api";
import { getAuthToken } from "@/lib/auth";
import type { AttackLogEntry, RiskLevel } from "@/types";

const MCP_TECHNIQUES: Record<string, boolean> = {
  prompt_injection: true,
  tool_injection: true,
  data_exfil: true,
  dos: false,
};

const OLLAMA_TECHNIQUES: Record<string, boolean> = {
  model_abuse: true,
  prompt_injection: true,
  admin_access: true,
  data_exfil: true,
};

const OPENCLAW_TECHNIQUES: Record<string, boolean> = {
  auth_bypass: true,
  config_access: true,
  credential_harvest: true,
  task_injection: true,
};

function logTypeColor(type: AttackLogEntry["type"]): string {
  switch (type) {
    case "REASONING": return "text-severity-info";
    case "PAYLOAD": return "text-severity-high";
    case "RESPONSE": return "text-muted-foreground";
    case "FINDING": return "text-severity-critical";
    default: return "text-foreground";
  }
}

function severityVariant(s?: RiskLevel) {
  return s || "info";
}

export function TestAgent() {
  const { id } = useParams<{ id: string }>();
  const { data: endpoint, isLoading } = useEndpointById(id);

  const defaultTechniques = endpoint?.protocol === "ollama"
    ? OLLAMA_TECHNIQUES
    : endpoint?.protocol === "openclaw"
      ? OPENCLAW_TECHNIQUES
      : MCP_TECHNIQUES;

  const [techniques, setTechniques] = useState<Record<string, boolean>>(defaultTechniques);

  // Update techniques when endpoint loads and protocol changes
  const prevProtocol = useRef<string | undefined>(undefined);
  useEffect(() => {
    if (endpoint && endpoint.protocol !== prevProtocol.current) {
      prevProtocol.current = endpoint.protocol;
      const proto = endpoint.protocol;
      setTechniques(
        proto === "ollama" ? OLLAMA_TECHNIQUES
        : proto === "openclaw" ? OPENCLAW_TECHNIQUES
        : MCP_TECHNIQUES
      );
    }
  }, [endpoint]);
  const [depth, setDepth] = useState("standard");
  const [maxSteps, setMaxSteps] = useState("20");
  const [isRunning, setIsRunning] = useState(false);
  const [logEntries, setLogEntries] = useState<AttackLogEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const cleanupRef = useRef<(() => void) | null>(null);

  // Clean up WebSocket on unmount
  useEffect(() => {
    return () => {
      cleanupRef.current?.();
    };
  }, []);

  const toggleTechnique = (key: string) => {
    setTechniques((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const handleStartAttack = useCallback(async () => {
    if (!id) return;

    setIsRunning(true);
    setLogEntries([]);
    setError(null);

    try {
      const selectedTechniques = Object.entries(techniques)
        .filter(([, enabled]) => enabled)
        .map(([key]) => key);

      const result = await startAttack(id, {
        techniques: selectedTechniques,
        depth,
        max_steps: parseInt(maxSteps, 10) || 20,
      });

      // Connect WebSocket to stream results (pass token for WS auth)
      const token = await getAuthToken();
      const cleanup = streamAttackLogs(
        result.attack_id,
        token,
        (entry) => {
          setLogEntries((prev) => [...prev, entry]);
        },
        () => {
          setIsRunning(false);
        },
        () => {
          setError("WebSocket connection lost");
          setIsRunning(false);
        },
      );

      cleanupRef.current = cleanup;
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to start attack");
      setIsRunning(false);
    }
  }, [id, techniques, depth, maxSteps]);

  if (isLoading) {
    return (
      <div className="px-6 py-6">
        <p className="text-muted-foreground">Loading endpoint...</p>
      </div>
    );
  }

  if (!endpoint) {
    return (
      <div className="px-6 py-6">
        <p className="text-muted-foreground">Endpoint not found.</p>
      </div>
    );
  }

  return (
    <div className="px-6 py-6 space-y-6">
      {/* Back */}
      <div className="flex items-center justify-between">
        <Link
          to={`/agent/${endpoint.id}`}
          className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground transition-colors"
        >
          <ArrowLeft className="h-4 w-4" />
          {endpoint.ip}:{endpoint.port}
        </Link>
        <Button
          variant="destructive"
          className="gap-2"
          onClick={handleStartAttack}
          disabled={isRunning}
        >
          <Swords className="h-4 w-4" />
          {isRunning ? "Running..." : "Start Attack"}
        </Button>
      </div>

      {/* Target Summary */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider">
            Target Summary
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-3 flex-wrap text-sm">
            <Badge variant="info">
              {endpoint.protocol === "openai_compat" ? "OpenAI" : endpoint.protocol.toUpperCase()}
            </Badge>
            <Badge variant={endpoint.auth_status === "none" ? "destructive" : "outline"}>
              {endpoint.auth_status === "none" ? "No Auth" : endpoint.auth_status}
            </Badge>
            <span className="text-muted-foreground">{endpoint.tool_count} tools</span>
            <span className="text-muted-foreground">
              {endpoint.system_prompt_extracted
                ? "System prompt extracted"
                : "System prompt not extracted"}
            </span>
            <span className="text-muted-foreground font-mono text-xs">{endpoint.url}</span>
          </div>
        </CardContent>
      </Card>

      {/* Attack Configuration */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-2">
            <Zap className="h-4 w-4" />
            Attack Configuration
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Techniques */}
          <div>
            <p className="text-sm text-muted-foreground mb-2">Techniques</p>
            <div className="flex flex-wrap gap-4">
              {Object.entries(techniques).map(([key, enabled]) => (
                <label key={key} className="flex items-center gap-2 text-sm cursor-pointer">
                  <input
                    type="checkbox"
                    checked={enabled}
                    onChange={() => toggleTechnique(key)}
                    className="h-4 w-4 accent-primary"
                    disabled={isRunning}
                  />
                  <span>{key.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())}</span>
                </label>
              ))}
            </div>
          </div>

          {/* Depth + Max Steps */}
          <div className="flex gap-4">
            <div className="space-y-1">
              <p className="text-sm text-muted-foreground">Depth</p>
              <Select
                value={depth}
                onChange={(e) => setDepth(e.target.value)}
                className="w-40"
                disabled={isRunning}
              >
                <option value="quick">Quick</option>
                <option value="standard">Standard</option>
                <option value="deep">Deep</option>
                <option value="exhaustive">Exhaustive</option>
              </Select>
            </div>
            <div className="space-y-1">
              <p className="text-sm text-muted-foreground">Max Steps</p>
              <Input
                type="number"
                value={maxSteps}
                onChange={(e) => setMaxSteps(e.target.value)}
                className="w-24"
                min={1}
                max={100}
                disabled={isRunning}
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Error */}
      {error && (
        <div className="bg-destructive/10 border border-destructive/30 text-destructive text-sm p-3 rounded">
          {error}
        </div>
      )}

      {/* Live Attack Log */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider">
            Live Attack Log
          </CardTitle>
        </CardHeader>
        <CardContent>
          <ScrollArea maxHeight="500px" className="bg-background border p-4">
            {logEntries.length === 0 ? (
              <p className="text-sm text-muted-foreground text-center py-8">
                {isRunning
                  ? "Connecting to target..."
                  : "Configure and start attack to see results"}
              </p>
            ) : (
              <div className="space-y-4 font-mono text-sm">
                {logEntries.map((entry, idx) => (
                  <div key={idx}>
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-xs text-muted-foreground">[{entry.timestamp}]</span>
                      <span className={`text-xs font-bold ${logTypeColor(entry.type)}`}>
                        {entry.type}
                      </span>
                      {entry.severity && (
                        <Badge variant={severityVariant(entry.severity)} className="text-[9px]">
                          {entry.severity.toUpperCase()}
                        </Badge>
                      )}
                    </div>
                    <p className="text-xs leading-relaxed whitespace-pre-wrap pl-4">
                      {entry.type === "PAYLOAD" && "> "}
                      {entry.type === "RESPONSE" && "< "}
                      {entry.content}
                    </p>
                  </div>
                ))}
                {isRunning && (
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <span className="inline-block w-2 h-2 bg-severity-info animate-pulse" />
                    Streaming...
                  </div>
                )}
              </div>
            )}
          </ScrollArea>

          {/* Progress footer */}
          {logEntries.length > 0 && (
            <div className="flex items-center justify-between mt-3">
              <div className="flex items-center gap-4 text-sm text-muted-foreground">
                <span>
                  Step {logEntries.filter((e) => e.type === "PAYLOAD").length}/{maxSteps}
                </span>
                <span>
                  {logEntries.filter((e) => e.type === "FINDING").length} finding(s)
                </span>
                <span>
                  {isRunning ? "Running..." : "Completed"}
                </span>
              </div>
              {!isRunning && logEntries.length > 0 && (
                <Link to={`/agent/${id}/results`}>
                  <Button variant="outline" size="sm" className="gap-2">
                    <FileText className="h-4 w-4" />
                    View Full Results
                  </Button>
                </Link>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
