import { useState } from "react";
import { Clock, Pause, Play, Square, Plus, Database, Radar } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table";
import {
  Dialog,
  DialogTrigger,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { mockScans } from "@/lib/mock-data";
import { useScans, useQueryPresets } from "@/hooks/useApi";
import { createScan, updateScanStatus, runScan } from "@/lib/api";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import type { Scan } from "@/types";

function timeRemaining(est: string): string {
  const diff = new Date(est).getTime() - Date.now();
  if (diff <= 0) return "\u2014";
  const hours = Math.floor(diff / 3600000);
  const mins = Math.floor((diff % 3600000) / 60000);
  if (hours > 0) return `${hours}h ${mins}m`;
  return `${mins}m`;
}

// Default query keys enabled for new ingestion scans.
// These are the high-value, low-noise queries.  The full list
// is fetched from /scans/query-presets at runtime.
const DEFAULT_QUERIES = [
  "mcp_protocol",
  "mcp_sse",
  "ollama",
  "vllm",
  "litellm",
  "openai_chat",
  "langserve",
  "openclaw",
  "open_webui",
  "comfyui",
  "stable_diffusion",
  "textgen_webui",
  "gradio",
  "streamlit",
];

export function Scans() {
  const queryClient = useQueryClient();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [scanType, setScanType] = useState<"active" | "ingestion">("active");

  // Active scan form state
  const [activeScan, setActiveScan] = useState({
    name: "",
    target: "",
    protocols: { mcp: true, openai_compat: true, langserve: true, autogen: false },
    ports: "80, 443, 3000, 8000, 8080, 8443, 8888",
    rate_limit: "1000",
  });

  // Ingestion scan form state
  const [ingestionScan, setIngestionScan] = useState({
    name: "",
    target: "", // optional CIDR filter
    source: "shodan",
    selectedQueries: new Set(DEFAULT_QUERIES),
    max_results_per_query: "100",
  });

  // API data
  const { data: apiData } = useScans();
  const { data: presetsData } = useQueryPresets();
  const presets = presetsData?.presets ?? [];
  const scans: Scan[] = apiData?.items?.length ? apiData.items : mockScans;

  const activeScans = scans.filter(
    (s) => s.status === "running" || s.status === "paused" || s.status === "queued"
  );
  const completedScans = scans.filter(
    (s) => s.status === "completed" || s.status === "failed"
  );

  // Mutations
  const createScanMutation = useMutation({
    mutationFn: (data: Parameters<typeof createScan>[0]) => createScan(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["scans"] });
      setDialogOpen(false);
      resetForms();
    },
  });

  const updateStatusMutation = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      updateScanStatus(id, status),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
  });

  const runScanMutation = useMutation({
    mutationFn: (id: string) => runScan(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
  });

  function resetForms() {
    setActiveScan({
      name: "",
      target: "",
      protocols: { mcp: true, openai_compat: true, langserve: true, autogen: false },
      ports: "80, 443, 3000, 8000, 8080, 8443, 8888",
      rate_limit: "1000",
    });
    setIngestionScan({
      name: "",
      target: "",
      source: "shodan",
      selectedQueries: new Set(DEFAULT_QUERIES),
      max_results_per_query: "100",
    });
  }

  const toggleQuery = (key: string) => {
    setIngestionScan((prev) => {
      const next = new Set(prev.selectedQueries);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return { ...prev, selectedQueries: next };
    });
  };

  const toggleProtocol = (key: string) => {
    setActiveScan((prev) => ({
      ...prev,
      protocols: {
        ...prev.protocols,
        [key]: !prev.protocols[key as keyof typeof prev.protocols],
      },
    }));
  };

  const handleStartScan = () => {
    if (scanType === "active") {
      const enabledProtocols = Object.entries(activeScan.protocols)
        .filter(([, enabled]) => enabled)
        .map(([key]) => key);
      const ports = activeScan.ports
        .split(",")
        .map((p) => parseInt(p.trim(), 10))
        .filter((p) => !isNaN(p));

      createScanMutation.mutate({
        name: activeScan.name || "Active Scan",
        type: "active",
        config: {
          target: activeScan.target,
          protocols: enabledProtocols as any,
          ports,
          rate_limit: parseInt(activeScan.rate_limit, 10) || 1000,
          timeout_ms: 5000,
          templates: [],
        },
      });
    } else {
      createScanMutation.mutate({
        name:
          ingestionScan.name ||
          `Shodan Ingestion${ingestionScan.target ? ` (${ingestionScan.target})` : ""}`,
        type: "ingestion",
        config: {
          type: "ingestion",
          source: ingestionScan.source,
          target: ingestionScan.target || undefined,
          queries: Array.from(ingestionScan.selectedQueries),
          max_results_per_query:
            parseInt(ingestionScan.max_results_per_query, 10) || 100,
        } as any,
      });
    }
  };

  const isIngestion = scanType === "ingestion";

  return (
    <div className="px-6 py-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">My Scans</h1>
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <DialogTrigger className="inline-flex items-center justify-center h-9 px-4 py-2 text-sm font-medium bg-primary text-primary-foreground shadow hover:bg-primary/90 gap-2">
            <Plus className="h-4 w-4" />
            New Scan
          </DialogTrigger>
          <DialogContent className="max-w-lg">
            <DialogHeader>
              <DialogTitle>New Scan</DialogTitle>
              <DialogDescription>
                {isIngestion
                  ? "Pull data from Shodan using preconfigured agent discovery queries."
                  : "Actively probe targets with httpx and Nuclei templates."}
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-4">
              {/* Scan type toggle */}
              <div className="grid grid-cols-2 gap-2">
                <button
                  type="button"
                  onClick={() => setScanType("active")}
                  className={`flex items-center justify-center gap-2 p-3 border text-sm font-medium transition-colors ${
                    !isIngestion
                      ? "border-primary bg-primary/10 text-primary"
                      : "border-border text-muted-foreground hover:text-foreground"
                  }`}
                >
                  <Radar className="h-4 w-4" />
                  Active Scan
                </button>
                <button
                  type="button"
                  onClick={() => setScanType("ingestion")}
                  className={`flex items-center justify-center gap-2 p-3 border text-sm font-medium transition-colors ${
                    isIngestion
                      ? "border-primary bg-primary/10 text-primary"
                      : "border-border text-muted-foreground hover:text-foreground"
                  }`}
                >
                  <Database className="h-4 w-4" />
                  3P Ingestion
                </button>
              </div>

              {/* Name */}
              <div className="space-y-1">
                <label className="text-sm text-muted-foreground">Name</label>
                <Input
                  value={isIngestion ? ingestionScan.name : activeScan.name}
                  onChange={(e) =>
                    isIngestion
                      ? setIngestionScan((p) => ({ ...p, name: e.target.value }))
                      : setActiveScan((p) => ({ ...p, name: e.target.value }))
                  }
                  placeholder={
                    isIngestion ? "e.g. Shodan MCP Discovery" : "e.g. Prod Range Scan"
                  }
                />
              </div>

              {isIngestion ? (
                <>
                  {/* CIDR filter (optional) */}
                  <div className="space-y-1">
                    <label className="text-sm text-muted-foreground">
                      CIDR Filter{" "}
                      <span className="text-xs">(optional — scopes queries to this range)</span>
                    </label>
                    <Input
                      value={ingestionScan.target}
                      onChange={(e) =>
                        setIngestionScan((p) => ({ ...p, target: e.target.value }))
                      }
                      placeholder="Leave empty for global search"
                      className="font-mono"
                    />
                  </div>

                  {/* Query presets */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <label className="text-sm text-muted-foreground">
                        Discovery Queries
                      </label>
                      <div className="flex gap-2">
                        <button
                          type="button"
                          className="text-xs text-primary hover:underline"
                          onClick={() =>
                            setIngestionScan((p) => ({
                              ...p,
                              selectedQueries: new Set(
                                presets.length
                                  ? presets.map((pr) => pr.key)
                                  : DEFAULT_QUERIES
                              ),
                            }))
                          }
                        >
                          All
                        </button>
                        <button
                          type="button"
                          className="text-xs text-muted-foreground hover:underline"
                          onClick={() =>
                            setIngestionScan((p) => ({
                              ...p,
                              selectedQueries: new Set(),
                            }))
                          }
                        >
                          None
                        </button>
                      </div>
                    </div>
                    <div className="space-y-1.5 max-h-48 overflow-y-auto">
                      {(presets.length ? presets : DEFAULT_QUERIES.map((k) => ({ key: k, description: k, query: "" }))).map(
                        (preset) => (
                          <label
                            key={preset.key}
                            className="flex items-start gap-2 text-sm cursor-pointer py-1 px-2 hover:bg-secondary/30 transition-colors"
                          >
                            <input
                              type="checkbox"
                              checked={ingestionScan.selectedQueries.has(preset.key)}
                              onChange={() => toggleQuery(preset.key)}
                              className="h-4 w-4 accent-primary mt-0.5"
                            />
                            <div className="flex-1 min-w-0">
                              <span className="font-medium">{preset.description}</span>
                              {preset.query && (
                                <p className="text-xs text-muted-foreground font-mono truncate">
                                  {preset.query}
                                </p>
                              )}
                            </div>
                          </label>
                        )
                      )}
                    </div>
                  </div>

                  {/* Max results per query */}
                  <div className="space-y-1">
                    <label className="text-sm text-muted-foreground">
                      Max Results per Query
                    </label>
                    <Input
                      type="number"
                      value={ingestionScan.max_results_per_query}
                      onChange={(e) =>
                        setIngestionScan((p) => ({
                          ...p,
                          max_results_per_query: e.target.value,
                        }))
                      }
                      className="w-32 font-mono"
                    />
                  </div>
                </>
              ) : (
                <>
                  {/* Active scan fields */}
                  <div className="space-y-1">
                    <label className="text-sm text-muted-foreground">Target CIDR</label>
                    <Input
                      value={activeScan.target}
                      onChange={(e) =>
                        setActiveScan((p) => ({ ...p, target: e.target.value }))
                      }
                      placeholder="e.g. 104.21.0.0/16"
                      className="font-mono"
                    />
                  </div>
                  <div className="space-y-1">
                    <label className="text-sm text-muted-foreground">Protocols</label>
                    <div className="flex gap-4">
                      {Object.entries(activeScan.protocols).map(([key, enabled]) => (
                        <label
                          key={key}
                          className="flex items-center gap-2 text-sm cursor-pointer"
                        >
                          <input
                            type="checkbox"
                            checked={enabled}
                            onChange={() => toggleProtocol(key)}
                            className="h-4 w-4 accent-primary"
                          />
                          {key === "openai_compat"
                            ? "OpenAI"
                            : key === "langserve"
                            ? "LangServe"
                            : key === "autogen"
                            ? "AutoGen"
                            : "MCP"}
                        </label>
                      ))}
                    </div>
                  </div>
                  <div className="space-y-1">
                    <label className="text-sm text-muted-foreground">Ports</label>
                    <Input
                      value={activeScan.ports}
                      onChange={(e) =>
                        setActiveScan((p) => ({ ...p, ports: e.target.value }))
                      }
                      placeholder="80, 443, 8080..."
                      className="font-mono"
                    />
                  </div>
                  <div className="space-y-1">
                    <label className="text-sm text-muted-foreground">
                      Rate Limit (req/s)
                    </label>
                    <Input
                      type="number"
                      value={activeScan.rate_limit}
                      onChange={(e) =>
                        setActiveScan((p) => ({ ...p, rate_limit: e.target.value }))
                      }
                      className="w-32"
                    />
                  </div>
                </>
              )}
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setDialogOpen(false)}>
                Cancel
              </Button>
              <Button
                onClick={handleStartScan}
                disabled={
                  createScanMutation.isPending ||
                  (isIngestion && ingestionScan.selectedQueries.size === 0) ||
                  (!isIngestion && !activeScan.target)
                }
              >
                {createScanMutation.isPending
                  ? "Creating..."
                  : isIngestion
                  ? `Run ${ingestionScan.selectedQueries.size} Queries`
                  : "Start Scan"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* Active Scans */}
      {activeScans.length > 0 && (
        <div className="space-y-3">
          <h2 className="text-sm font-medium text-muted-foreground uppercase tracking-wider">
            Active Scans
          </h2>
          {activeScans.map((scan) => (
            <Card key={scan.id}>
              <CardContent className="p-4">
                <div className="flex items-start justify-between mb-3">
                  <div>
                    <h3 className="font-semibold text-white">{scan.name}</h3>
                    <p className="text-sm text-muted-foreground font-mono">
                      {scan.config?.target || "Global"}
                      {scan.config?.queries
                        ? ` · ${(scan.config.queries as string[]).length} queries`
                        : scan.config?.protocols?.length
                        ? ` · ${scan.config.protocols
                            .map((p: string) =>
                              p === "openai_compat"
                                ? "OpenAI"
                                : p === "langserve"
                                ? "LangServe"
                                : p.toUpperCase()
                            )
                            .join(", ")}`
                        : ""}
                    </p>
                  </div>
                  <div className="flex gap-2">
                    {scan.status === "queued" && (
                      <Button
                        variant="default"
                        size="sm"
                        className="gap-1"
                        onClick={() => runScanMutation.mutate(scan.id)}
                        disabled={runScanMutation.isPending}
                      >
                        <Play className="h-3 w-3" />
                        Run
                      </Button>
                    )}
                    {scan.status === "running" && (
                      <Button
                        variant="outline"
                        size="sm"
                        className="gap-1"
                        onClick={() =>
                          updateStatusMutation.mutate({
                            id: scan.id,
                            status: "paused",
                          })
                        }
                        disabled={updateStatusMutation.isPending}
                      >
                        <Pause className="h-3 w-3" />
                        Pause
                      </Button>
                    )}
                    {scan.status === "paused" && (
                      <Button
                        variant="outline"
                        size="sm"
                        className="gap-1"
                        onClick={() =>
                          updateStatusMutation.mutate({
                            id: scan.id,
                            status: "running",
                          })
                        }
                        disabled={updateStatusMutation.isPending}
                      >
                        <Play className="h-3 w-3" />
                        Resume
                      </Button>
                    )}
                    <Button
                      variant="destructive"
                      size="sm"
                      className="gap-1"
                      onClick={() =>
                        updateStatusMutation.mutate({
                          id: scan.id,
                          status: "stopped",
                        })
                      }
                      disabled={updateStatusMutation.isPending}
                    >
                      <Square className="h-3 w-3" />
                      Stop
                    </Button>
                  </div>
                </div>

                <Progress
                  value={scan.progress?.percent_complete ?? 0}
                  className="mb-2"
                />

                <div className="flex items-center justify-between text-sm">
                  <div className="flex gap-4 text-muted-foreground">
                    <span>
                      <span className="text-foreground font-mono">
                        {scan.progress?.agents_found ?? 0}
                      </span>{" "}
                      agents found
                    </span>
                    <span>
                      <span className="font-mono">
                        {(scan.progress?.scanned ?? 0).toLocaleString()}
                      </span>
                      /
                      <span className="font-mono">
                        {(scan.progress?.total_hosts ?? 0).toLocaleString()}
                      </span>{" "}
                      hosts
                    </span>
                  </div>
                  {scan.progress?.estimated_completion && (
                    <div className="flex items-center gap-1 text-xs text-muted-foreground">
                      <Clock className="h-3 w-3" />
                      ETA: {timeRemaining(scan.progress.estimated_completion)}
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Completed Scans */}
      <div className="space-y-3">
        <h2 className="text-sm font-medium text-muted-foreground uppercase tracking-wider">
          Completed Scans
        </h2>
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Target</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Found</TableHead>
                <TableHead>Critical</TableHead>
                <TableHead>Date</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {completedScans.map((scan) => (
                <TableRow key={scan.id}>
                  <TableCell className="font-medium">{scan.name}</TableCell>
                  <TableCell className="font-mono text-xs">
                    {scan.config?.type === "ingestion"
                      ? scan.config?.target || "Global"
                      : scan.config?.target ?? "\u2014"}
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant={
                        scan.status === "failed" ? "destructive" : "secondary"
                      }
                      className="text-[10px]"
                    >
                      {scan.status === "failed"
                        ? "FAILED"
                        : scan.config?.type === "ingestion"
                        ? "INGESTION"
                        : "ACTIVE"}
                    </Badge>
                  </TableCell>
                  <TableCell className="font-mono">
                    {(
                      scan.results_summary?.total_endpoints ?? 0
                    ).toLocaleString()}
                  </TableCell>
                  <TableCell>
                    <span className="font-mono text-severity-critical">
                      {scan.results_summary?.by_risk?.critical ?? 0}
                    </span>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {new Date(scan.created_at).toLocaleDateString()}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      </div>
    </div>
  );
}
