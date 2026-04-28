import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, FileDown, RotateCcw, ChevronDown, ChevronRight } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useEndpointById, useAnalysis } from "@/hooks/useApi";

export function TestInfo() {
  const { id } = useParams<{ id: string }>();
  const { data: endpoint, isLoading: epLoading } = useEndpointById(id);
  const { data: analysis, isLoading: anLoading } = useAnalysis(id);
  const testing = analysis?.testing;

  const [expandedTests, setExpandedTests] = useState<Set<string>>(new Set());
  const [logExpanded, setLogExpanded] = useState(false);

  const toggleTest = (testId: string) => {
    setExpandedTests((prev) => {
      const next = new Set(prev);
      if (next.has(testId)) next.delete(testId);
      else next.add(testId);
      return next;
    });
  };

  if (epLoading || anLoading) {
    return (
      <div className="px-6 py-6">
        <p className="text-muted-foreground">Loading results...</p>
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

  if (!testing || !testing.test_results?.length) {
    return (
      <div className="px-6 py-6 space-y-6">
        <Link
          to={`/agent/${endpoint.id}`}
          className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground transition-colors"
        >
          <ArrowLeft className="h-4 w-4" />
          {endpoint.ip}:{endpoint.port}
        </Link>
        <Card>
          <CardContent className="p-6 text-center">
            <p className="text-muted-foreground">
              No test results yet.{" "}
              <Link to={`/agent/${endpoint.id}/test`} className="text-primary hover:underline">
                Run an attack
              </Link>{" "}
              to generate results.
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  const successCount = testing.test_results.filter((t) => t.success).length;
  const criticalCount = testing.test_results.filter(
    (t) => t.severity === "critical" && t.success,
  ).length;

  return (
    <div className="px-6 py-6 space-y-6">
      {/* Back */}
      <Link
        to={`/agent/${endpoint.id}`}
        className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground transition-colors"
      >
        <ArrowLeft className="h-4 w-4" />
        {endpoint.ip}:{endpoint.port} · Test Results
      </Link>

      {/* Test run header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-white">
            Attack Results
          </h2>
          <p className="text-sm text-muted-foreground">
            {testing.last_tested_at
              ? new Date(testing.last_tested_at).toLocaleDateString()
              : "—"}{" "}
            · {testing.status?.toUpperCase() || "COMPLETED"}
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" className="gap-2" onClick={() => {}}>
            <FileDown className="h-4 w-4" />
            Export PDF
          </Button>
          <Link to={`/agent/${endpoint.id}/test`}>
            <Button variant="secondary" className="gap-2">
              <RotateCcw className="h-4 w-4" />
              Re-run
            </Button>
          </Link>
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-3 gap-4">
        <Card>
          <CardContent className="p-6 text-center">
            <p className="text-3xl font-mono font-bold text-white">
              {testing.test_results.length}
            </p>
            <p className="text-sm text-muted-foreground">Tests Run</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-6 text-center">
            <p className="text-3xl font-mono font-bold text-severity-high">
              {successCount}
            </p>
            <p className="text-sm text-muted-foreground">Succeeded</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-6 text-center">
            <p className="text-3xl font-mono font-bold text-severity-critical">
              {criticalCount}
            </p>
            <p className="text-sm text-muted-foreground">Critical</p>
          </CardContent>
        </Card>
      </div>

      {/* Attack graph */}
      {testing.attack_graph?.nodes?.length ? (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider">
              Attack Graph (Realized)
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="bg-secondary/30 border p-6">
              <div className="flex items-center justify-center gap-2 flex-wrap">
                {testing.attack_graph.nodes.map((node, idx) => (
                  <div key={node.id} className="flex items-center gap-2">
                    <div
                      className={`px-3 py-2 border text-xs font-mono ${
                        node.success
                          ? node.type === "impact"
                            ? "border-severity-critical bg-severity-critical/20 text-severity-critical font-bold"
                            : "border-severity-low bg-severity-low/10 text-severity-low"
                          : "border-muted bg-muted/20 text-muted-foreground"
                      }`}
                    >
                      {node.label}
                      {node.success !== undefined && (
                        <span className="ml-1">
                          {node.success ? " [OK]" : " [FAIL]"}
                        </span>
                      )}
                    </div>
                    {idx < testing.attack_graph.nodes.length - 1 && (
                      <span className="text-muted-foreground font-bold">
                        &#8658;
                      </span>
                    )}
                  </div>
                ))}
              </div>
              <p className="text-xs text-muted-foreground text-center mt-4">
                Green = exploited successfully, Gray = not attempted
              </p>
            </div>
          </CardContent>
        </Card>
      ) : null}

      {/* Findings */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider">
            Findings ({successCount})
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-0">
          {testing.test_results.map((test, idx) => (
            <div key={test.test_id || idx}>
              {idx > 0 && <Separator className="my-1" />}
              <div
                className="py-3 cursor-pointer"
                onClick={() => toggleTest(test.test_id || `test-${idx}`)}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    {expandedTests.has(test.test_id || `test-${idx}`) ? (
                      <ChevronDown className="h-4 w-4 text-muted-foreground" />
                    ) : (
                      <ChevronRight className="h-4 w-4 text-muted-foreground" />
                    )}
                    <span className="text-sm font-medium">
                      #{idx + 1} ·{" "}
                      {(test.technique || "unknown")
                        .replace(/_/g, " ")
                        .replace(/\b\w/g, (c) => c.toUpperCase())}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant={test.success ? test.severity : "secondary"}>
                      {(test.severity || "info").toUpperCase()}
                    </Badge>
                    <Badge
                      variant={test.success ? "destructive" : "outline"}
                      className="text-[10px]"
                    >
                      {test.success ? "SUCCESS" : "FAILED"}
                    </Badge>
                  </div>
                </div>

                {expandedTests.has(test.test_id || `test-${idx}`) && (
                  <div className="mt-3 pl-7 space-y-2 text-sm">
                    <div>
                      <span className="text-muted-foreground">Category: </span>
                      <span className="font-mono">{test.category || "—"}</span>
                    </div>
                    {test.chain && (
                      <div>
                        <span className="text-muted-foreground">Chain: </span>
                        <span className="font-mono">
                          {test.chain.join(" -> ")}
                        </span>
                      </div>
                    )}
                    <div>
                      <p className="text-muted-foreground mb-1">Payload:</p>
                      <pre className="font-mono text-xs bg-secondary/50 p-3 border whitespace-pre-wrap">
                        {test.payload || "—"}
                      </pre>
                    </div>
                    <div>
                      <p className="text-muted-foreground mb-1">Response:</p>
                      <pre className="font-mono text-xs bg-secondary/50 p-3 border whitespace-pre-wrap">
                        {test.response || "—"}
                      </pre>
                    </div>
                  </div>
                )}
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      {/* Full Exploitation Log */}
      {testing.exploitation_log?.length ? (
        <Card>
          <CardHeader
            className="pb-3 cursor-pointer"
            onClick={() => setLogExpanded(!logExpanded)}
          >
            <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-2">
              {logExpanded ? (
                <ChevronDown className="h-4 w-4" />
              ) : (
                <ChevronRight className="h-4 w-4" />
              )}
              Full Exploitation Log ({testing.exploitation_log.length} steps)
            </CardTitle>
          </CardHeader>
          {logExpanded && (
            <CardContent>
              <ScrollArea maxHeight="400px">
                <div className="space-y-4">
                  {testing.exploitation_log.map((entry) => (
                    <div
                      key={entry.step}
                      className="border-l-2 border-primary/30 pl-4"
                    >
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-xs font-mono text-muted-foreground">
                          Step {entry.step}
                        </span>
                        {entry.timestamp && (
                          <span className="text-xs text-muted-foreground">
                            {new Date(entry.timestamp).toLocaleTimeString()}
                          </span>
                        )}
                      </div>
                      <p className="text-sm text-severity-info mb-1">
                        <span className="font-semibold">Reasoning: </span>
                        {entry.reasoning}
                      </p>
                      <p className="text-sm text-severity-high mb-1">
                        <span className="font-semibold">Action: </span>
                        {entry.action}
                      </p>
                      <p className="text-sm">
                        <span className="font-semibold">Result: </span>
                        {entry.result}
                      </p>
                    </div>
                  ))}
                </div>
              </ScrollArea>
            </CardContent>
          )}
        </Card>
      ) : null}
    </div>
  );
}
