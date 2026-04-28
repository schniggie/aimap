import { useState } from "react";
import {
  Plus,
  TrendingUp,
  TrendingDown,
  Minus,
  Eye,
  Scan,
  Database,
  Pencil,
  Trash2,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import {
  Dialog,
  DialogTrigger,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { mockRanges } from "@/lib/mock-data";
import { useRanges } from "@/hooks/useApi";
import { createRange, deleteRange, triggerRangeScan, triggerRangeIngestion } from "@/lib/api";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import type { MonitoredRange } from "@/types";

function trendIcon(direction: string) {
  switch (direction) {
    case "increasing":
      return <TrendingUp className="h-4 w-4 text-severity-critical" />;
    case "decreasing":
      return <TrendingDown className="h-4 w-4 text-severity-low" />;
    default:
      return <Minus className="h-4 w-4 text-muted-foreground" />;
  }
}

function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const hours = Math.floor(diff / 3600000);
  if (hours < 1) return "< 1h ago";
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function timeUntil(dateStr: string): string {
  const diff = new Date(dateStr).getTime() - Date.now();
  if (diff <= 0) return "now";
  const hours = Math.floor(diff / 3600000);
  if (hours < 1) return "< 1h";
  return `${hours}h`;
}

export function Ranges() {
  const queryClient = useQueryClient();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [newRange, setNewRange] = useState({
    name: "",
    cidr: "",
    interval: "24",
    monitoring: true,
  });

  // API data
  const { data: apiData } = useRanges();
  const ranges: MonitoredRange[] = apiData?.items?.length ? apiData.items : mockRanges;

  // Mutations
  const createRangeMutation = useMutation({
    mutationFn: (data: Parameters<typeof createRange>[0]) => createRange(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ranges"] });
      setDialogOpen(false);
      setNewRange({ name: "", cidr: "", interval: "24", monitoring: true });
    },
  });

  const deleteRangeMutation = useMutation({
    mutationFn: (id: string) => deleteRange(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ranges"] });
    },
  });

  const triggerScanMutation = useMutation({
    mutationFn: (id: string) => triggerRangeScan(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ranges"] });
      queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
  });

  const triggerIngestionMutation = useMutation({
    mutationFn: (id: string) => triggerRangeIngestion(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ranges"] });
      queryClient.invalidateQueries({ queryKey: ["scans"] });
    },
  });

  const handleAddRange = () => {
    createRangeMutation.mutate({
      name: newRange.name,
      cidr: newRange.cidr,
      monitoring: {
        enabled: newRange.monitoring,
        interval_hours: parseInt(newRange.interval, 10),
      },
    });
  };

  return (
    <div className="px-6 py-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">IP Range Monitor</h1>
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <DialogTrigger className="inline-flex items-center justify-center h-9 px-4 py-2 text-sm font-medium bg-primary text-primary-foreground shadow hover:bg-primary/90 gap-2">
            <Plus className="h-4 w-4" />
            Add Range
          </DialogTrigger>
          <DialogContent className="max-w-md">
            <DialogHeader>
              <DialogTitle>Add Range</DialogTitle>
              <DialogDescription>
                Define a new IP range to monitor for AI agents.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-4">
              <div className="space-y-1">
                <label className="text-sm text-muted-foreground">Name</label>
                <Input
                  value={newRange.name}
                  onChange={(e) => setNewRange((p) => ({ ...p, name: e.target.value }))}
                  placeholder="e.g. Production AWS"
                />
              </div>
              <div className="space-y-1">
                <label className="text-sm text-muted-foreground">CIDR</label>
                <Input
                  value={newRange.cidr}
                  onChange={(e) => setNewRange((p) => ({ ...p, cidr: e.target.value }))}
                  placeholder="e.g. 10.0.0.0/16"
                  className="font-mono"
                />
              </div>
              <div className="space-y-1">
                <label className="text-sm text-muted-foreground">Scan Interval</label>
                <Select
                  value={newRange.interval}
                  onChange={(e) => setNewRange((p) => ({ ...p, interval: e.target.value }))}
                >
                  <option value="6">Every 6 hours</option>
                  <option value="12">Every 12 hours</option>
                  <option value="24">Every 24 hours</option>
                  <option value="48">Every 48 hours</option>
                  <option value="168">Every 7 days</option>
                </Select>
              </div>
              <label className="flex items-center gap-2 text-sm cursor-pointer">
                <input
                  type="checkbox"
                  checked={newRange.monitoring}
                  onChange={(e) =>
                    setNewRange((p) => ({ ...p, monitoring: e.target.checked }))
                  }
                  className="h-4 w-4 accent-primary"
                />
                Enable monitoring
              </label>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setDialogOpen(false)}>
                Cancel
              </Button>
              <Button
                onClick={handleAddRange}
                disabled={createRangeMutation.isPending}
              >
                {createRangeMutation.isPending ? "Adding..." : "Add Range"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* Range cards */}
      <div className="space-y-4">
        {ranges.map((range) => (
          <Card key={range.id}>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-lg font-semibold text-white">
                    {range.name}
                  </CardTitle>
                  <p className="text-sm text-muted-foreground font-mono">{range.cidr}</p>
                </div>
                <div className="flex items-center gap-2">
                  {range.monitoring.enabled && (
                    <Badge variant="info" className="text-[10px]">MONITORING</Badge>
                  )}
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Agent stats */}
              <div className="flex items-center gap-3">
                <span className="text-sm text-muted-foreground">Agents:</span>
                <span className="text-lg font-mono font-bold text-white">
                  {range.stats.total_endpoints}
                </span>
                {range.stats.trend && (
                  <span className="flex items-center gap-1 text-sm">
                    {trendIcon(range.stats.trend.direction)}
                    <span className="text-muted-foreground">
                      +{range.stats.total_endpoints - range.stats.trend.endpoints_7d_ago} from 7d ago,
                      +{range.stats.total_endpoints - range.stats.trend.endpoints_30d_ago} from 30d ago
                    </span>
                  </span>
                )}
              </div>

              {/* Risk breakdown */}
              <div className="flex items-center gap-4 text-sm">
                <span>
                  <span className="text-severity-critical font-mono font-bold">
                    {range.stats.by_risk.critical ?? 0}
                  </span>{" "}
                  <span className="text-muted-foreground">Critical</span>
                </span>
                <span>
                  <span className="text-severity-high font-mono font-bold">
                    {range.stats.by_risk.high ?? 0}
                  </span>{" "}
                  <span className="text-muted-foreground">High</span>
                </span>
                <span>
                  <span className="text-severity-medium font-mono font-bold">
                    {range.stats.by_risk.medium ?? 0}
                  </span>{" "}
                  <span className="text-muted-foreground">Medium</span>
                </span>
                <span>
                  <span className="text-muted-foreground">No Auth: </span>
                  <span className="font-mono font-bold text-foreground">
                    {range.stats.no_auth_count}
                  </span>
                </span>
              </div>

              {/* Sparkline placeholder */}
              <div className="h-16 bg-secondary/20 border border-dashed flex items-center justify-center">
                <span className="text-xs text-muted-foreground">
                  Trend Sparkline — Coming Soon
                </span>
              </div>

              <Separator />

              {/* Monitoring info */}
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4 text-xs text-muted-foreground">
                  <span>
                    Every {range.monitoring.interval_hours}h
                  </span>
                  {range.monitoring.last_scanned_at && (
                    <span>
                      Last: {timeAgo(range.monitoring.last_scanned_at)}
                    </span>
                  )}
                  {range.monitoring.next_scan_at && (
                    <span>
                      Next: {timeUntil(range.monitoring.next_scan_at)}
                    </span>
                  )}
                </div>
                <div className="flex gap-2">
                  <Button variant="outline" size="sm" className="gap-1 text-xs">
                    <Eye className="h-3 w-3" />
                    View Endpoints
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    className="gap-1 text-xs"
                    onClick={() => triggerScanMutation.mutate(range.id)}
                    disabled={triggerScanMutation.isPending}
                  >
                    <Scan className="h-3 w-3" />
                    {triggerScanMutation.isPending ? "Starting..." : "Active Scan"}
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    className="gap-1 text-xs"
                    onClick={() => triggerIngestionMutation.mutate(range.id)}
                    disabled={triggerIngestionMutation.isPending}
                  >
                    <Database className="h-3 w-3" />
                    {triggerIngestionMutation.isPending ? "Starting..." : "3P Scan"}
                  </Button>
                  <Button variant="ghost" size="sm" className="gap-1 text-xs">
                    <Pencil className="h-3 w-3" />
                    Edit
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="gap-1 text-xs text-severity-critical hover:text-severity-critical"
                    onClick={() => deleteRangeMutation.mutate(range.id)}
                    disabled={deleteRangeMutation.isPending}
                  >
                    <Trash2 className="h-3 w-3" />
                    {deleteRangeMutation.isPending ? "Deleting..." : "Delete"}
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
