import { useEffect, useState, useMemo } from "react";
import DashboardLayout from "@/components/DashboardLayout";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { getRiskProfile } from "@/lib/risk";
import { useTheme } from "@/contexts/ThemeContext";
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  ArrowDownLeft,
  ArrowUpRight,
  Check,
  CheckCircle2,
  Copy,
  Download,
  ExternalLink,
  Flame,
  Globe,
  Laptop,
  Layers,
  Loader2,
  Lock,
  Pause,
  Play,
  Radar,
  Radio,
  RefreshCw,
  Search,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Terminal,
  Wifi,
  Zap,
  Users,
} from "lucide-react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { useLocation } from "wouter";

interface ConnectionItem {
  timestamp: string;
  sourceIp: string;
  destinationIp: string;
  sourcePort: string;
  destinationPort: string;
  protocol: string;
  service?: string;
  action: string;
  severity: string;
  threatStatus: string;
  state: string;
  processName?: string;
  hostname?: string;
}

interface NetworkScanResult {
  status: "alert" | "normal";
  alert: boolean;
  riskScore: number;
  vulnerabilities: string[];
  reasoning: string;
  remediationSteps: string[];
  source: "gemini" | "heuristics";
  snapshotPreview: string;
  connections: ConnectionItem[];
  target?: string;
  connectionStats: {
    totalConnections: number;
    allowed: number;
    blocked: number;
    suspicious: number;
    threats: number;
  };
  protocols?: Record<string, number>;
}

export default function NetworkMonitor() {
  const { theme } = useTheme();
  const isDark = theme === "dark";
  const trpcUtils = trpc.useUtils();
  const [, setLocation] = useLocation();

  // Queries
  const endpointsQuery = trpc.endpoints.list.useQuery();
  const isolateMutation = trpc.endpoints.isolate.useMutation({
    onSuccess: (data) => {
      toast.success(data.message);
      void endpointsQuery.refetch();
    },
  });

  // State
  const [result, setResult] = useState<NetworkScanResult | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");
  const [autoScanEnabled, setAutoScanEnabled] = useState(false);
  const [refreshIntervalSec, setRefreshIntervalSec] = useState<number>(5);

  // Target selection: "fleet" | "local" | endpointId string
  const [selectedTarget, setSelectedTarget] = useState<string>(() => {
    if (typeof window !== "undefined") {
      const params = new URLSearchParams(window.location.search);
      const epId = params.get("endpointId");
      if (epId) return epId;
    }
    return "fleet";
  });

  // Sync if URL search params change
  useEffect(() => {
    if (typeof window !== "undefined") {
      const params = new URLSearchParams(window.location.search);
      const epId = params.get("endpointId");
      if (epId && epId !== selectedTarget) {
        setSelectedTarget(epId);
      }
    }
  }, []);

  // Filters
  const [searchFilter, setSearchFilter] = useState("");
  const [protocolFilter, setProtocolFilter] = useState<string>("ALL");
  const [statusFilter, setStatusFilter] = useState<string>("ALL");
  const [completedRemediations, setCompletedRemediations] = useState<Record<number, boolean>>({});

  const endpointsList = endpointsQuery.data || [];

  const runScan = async () => {
    setIsLoading(true);
    setError("");

    try {
      const payload: { target: string; endpointId?: number } = {
        target: selectedTarget === "local" ? "local" : selectedTarget === "fleet" ? "fleet" : "endpoint",
      };

      if (selectedTarget !== "local" && selectedTarget !== "fleet") {
        payload.endpointId = Number(selectedTarget);
      }

      const response = await fetch("/api/live-network", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const data = await response.json();
      if (!response.ok || data.error) {
        throw new Error(data.error || "Live network capture failed");
      }

      setResult(data);
      void trpcUtils.threats.list.invalidate();
      void trpcUtils.dashboard.metrics.invalidate();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Live network capture failed");
    } finally {
      setIsLoading(false);
    }
  };

  // Initial scan & on target change
  useEffect(() => {
    void runScan();
  }, [selectedTarget]);

  // Live Auto-Scan Interval
  useEffect(() => {
    if (!autoScanEnabled) return;
    const interval = window.setInterval(runScan, refreshIntervalSec * 1000);
    return () => window.clearInterval(interval);
  }, [autoScanEnabled, refreshIntervalSec, selectedTarget]);

  const riskProfile = result ? getRiskProfile(result.riskScore) : null;
  const riskGlow = riskProfile ? (isDark ? riskProfile.glowDark : riskProfile.glowLight) : "";

  // Filtered Connections
  const filteredConnections = useMemo(() => {
    if (!result?.connections) return [];
    return result.connections.filter((conn) => {
      const matchesSearch =
        !searchFilter ||
        conn.sourceIp.includes(searchFilter) ||
        conn.destinationIp.includes(searchFilter) ||
        (conn.service && conn.service.toLowerCase().includes(searchFilter.toLowerCase())) ||
        (conn.processName && conn.processName.toLowerCase().includes(searchFilter.toLowerCase())) ||
        conn.destinationPort.includes(searchFilter) ||
        (conn.hostname && conn.hostname.toLowerCase().includes(searchFilter.toLowerCase()));

      const matchesProtocol = protocolFilter === "ALL" || conn.protocol.toUpperCase() === protocolFilter.toUpperCase();

      const matchesStatus =
        statusFilter === "ALL" ||
        (statusFilter === "SUSPICIOUS" && conn.threatStatus !== "normal") ||
        (statusFilter === "ALLOWED" && conn.action === "ALLOW") ||
        (statusFilter === "BLOCKED" && conn.action === "BLOCK");

      return matchesSearch && matchesProtocol && matchesStatus;
    });
  }, [result?.connections, searchFilter, protocolFilter, statusFilter]);

  // Export CSV
  const exportCsv = () => {
    if (!result?.connections || result.connections.length === 0) {
      toast.error("No network connections to export");
      return;
    }

    const headers = ["Timestamp", "Source IP", "Destination IP", "Destination Port", "Protocol", "Service", "Process", "Action", "Threat Status"];
    const rows = result.connections.map((c) => [
      c.timestamp,
      c.sourceIp,
      c.destinationIp,
      c.destinationPort,
      c.protocol,
      c.service || "N/A",
      c.processName || "N/A",
      c.action,
      c.threatStatus,
    ]);

    const csvContent = [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.setAttribute("download", `network-capture-${new Date().toISOString().slice(0, 19)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    toast.success("Network flow capture exported as CSV");
  };

  const toggleRemediation = (idx: number) => {
    setCompletedRemediations((prev) => ({ ...prev, [idx]: !prev[idx] }));
  };

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Top Header & Target Selector */}
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border/40 pb-5">
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-cyan-600 dark:text-cyan-400">
              <Radar className="h-5 w-5 animate-spin-slow" />
              <span className="text-xs font-bold uppercase tracking-widest">Deep Packet & Telemetry Inspection</span>
            </div>
            <h1 className="text-3xl font-black tracking-tight">Enterprise Network Monitor</h1>
            <p className="text-xs text-muted-foreground">
              Real-time traffic capture, C2 beacon detection, protocol intelligence, and instant SOC mitigation.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Target Selector Dropdown */}
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold text-muted-foreground whitespace-nowrap">Target Workstation:</span>
              <Select value={selectedTarget} onValueChange={setSelectedTarget}>
                <SelectTrigger className="w-[240px] text-xs h-9 bg-card">
                  <SelectValue placeholder="Select monitoring target" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="fleet">
                    <span className="flex items-center gap-2 font-medium">
                      <Layers className="h-3.5 w-3.5 text-cyan-500" /> All Enterprise Fleet (Aggregate)
                    </span>
                  </SelectItem>
                  <SelectItem value="local">
                    <span className="flex items-center gap-2 font-medium">
                      <Server className="h-3.5 w-3.5 text-blue-500" /> Local Host Gateway
                    </span>
                  </SelectItem>
                  {endpointsList.map((ep) => (
                    <SelectItem key={ep.id} value={String(ep.id)}>
                      <span className="flex items-center gap-2 font-medium">
                        <Laptop className="h-3.5 w-3.5 text-emerald-500" /> {ep.name} ({ep.os ? ep.os.split(" ")[0] : "PC"})
                      </span>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <Button
              size="sm"
              onClick={runScan}
              disabled={isLoading}
              className="gap-2 bg-cyan-600 hover:bg-cyan-500 text-white font-semibold h-9"
            >
              {isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
              Capture Now
            </Button>

            <Button
              size="sm"
              variant={autoScanEnabled ? "default" : "outline"}
              onClick={() => setAutoScanEnabled((p) => !p)}
              className={`gap-2 h-9 ${autoScanEnabled ? "bg-emerald-600 hover:bg-emerald-500 text-white" : ""}`}
            >
              {autoScanEnabled ? <Pause className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5" />}
              {autoScanEnabled ? `Streaming (${refreshIntervalSec}s)` : "Live Stream"}
            </Button>

            {autoScanEnabled && (
              <Select
                value={String(refreshIntervalSec)}
                onValueChange={(val) => setRefreshIntervalSec(Number(val))}
              >
                <SelectTrigger className="w-[70px] text-xs h-9">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="3">3s</SelectItem>
                  <SelectItem value="5">5s</SelectItem>
                  <SelectItem value="10">10s</SelectItem>
                  <SelectItem value="30">30s</SelectItem>
                </SelectContent>
              </Select>
            )}

            <Button variant="outline" size="sm" onClick={exportCsv} className="gap-1.5 h-9 text-xs">
              <Download className="h-3.5 w-3.5" /> Export CSV
            </Button>
          </div>
        </div>

        {/* Employee Workstation Quick Monitoring Hub */}
        <div className="flex flex-col gap-2.5 rounded-2xl border border-border bg-card/85 p-3.5 backdrop-blur-sm shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-foreground flex items-center gap-1.5 uppercase tracking-wider">
              <Users className="w-3.5 h-3.5 text-primary" />
              Employee Traffic Monitoring Hub
            </span>
            <span className="text-[11px] text-muted-foreground">
              Select an employee below to inspect their real-time sockets & data transfer
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2 pt-0.5">
            <button
              onClick={() => setSelectedTarget("fleet")}
              className={`px-3 py-1.5 rounded-xl text-xs font-medium flex items-center gap-1.5 transition-all ${
                selectedTarget === "fleet"
                  ? "bg-primary text-primary-foreground font-semibold shadow-xs"
                  : "bg-muted/50 border border-border text-foreground hover:bg-muted"
              }`}
            >
              <Layers className="w-3.5 h-3.5" /> All Enterprise Fleet
            </button>

            <button
              onClick={() => setSelectedTarget("local")}
              className={`px-3 py-1.5 rounded-xl text-xs font-medium flex items-center gap-1.5 transition-all ${
                selectedTarget === "local"
                  ? "bg-primary text-primary-foreground font-semibold shadow-xs"
                  : "bg-muted/50 border border-border text-foreground hover:bg-muted"
              }`}
            >
              <Server className="w-3.5 h-3.5" /> Local Gateway
            </button>

            {endpointsList.map((ep) => {
              const isSelected = selectedTarget === String(ep.id);
              const isWarning = ep.status === "warning";
              return (
                <button
                  key={ep.id}
                  onClick={() => setSelectedTarget(String(ep.id))}
                  className={`px-3 py-1.5 rounded-xl text-xs font-medium flex items-center gap-1.5 transition-all ${
                    isSelected
                      ? "bg-primary text-primary-foreground font-semibold shadow-xs ring-1 ring-primary"
                      : isWarning
                      ? "bg-amber-500/10 border border-amber-500/30 text-amber-700 dark:text-amber-300 hover:bg-amber-500/20"
                      : "bg-muted/50 border border-border text-foreground hover:bg-muted"
                  }`}
                >
                  <span
                    className={`w-2 h-2 rounded-full ${
                      isWarning ? "bg-amber-500 animate-pulse" : "bg-emerald-500"
                    }`}
                  />
                  <span>{ep.name.split(" — ")[0] || ep.name}</span>
                  <span className="text-[10px] opacity-75 font-mono">
                    ({ep.name.includes("—") ? ep.name.split(" — ")[1]?.split(" ")[0] : ep.hostname || "PC"})
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        {error && (
          <div className="flex items-center justify-between gap-3 rounded-xl border border-amber-500/30 bg-amber-500/10 p-3.5 text-xs text-amber-700 dark:text-amber-300">
            <div className="flex items-center gap-2.5">
              <AlertTriangle className="h-4 w-4 text-amber-500 shrink-0" />
              <span>{error}</span>
            </div>
            <Button size="sm" variant="outline" onClick={runScan} className="h-7 text-xs border-amber-500/30 text-amber-700 dark:text-amber-300 hover:bg-amber-500/20">
              Retry
            </Button>
          </div>
        )}

        {/* Live Traffic Stats Bar */}
        {result && (
          <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
            <Card className="border-border/60 bg-card/60 backdrop-blur-sm">
              <CardContent className="p-3.5">
                <span className="text-[10px] uppercase font-bold text-muted-foreground tracking-wider block">
                  Active Connections
                </span>
                <p className="text-2xl font-black mt-1">{result.connectionStats.totalConnections}</p>
                <p className="text-[10px] text-muted-foreground">Monitored sockets</p>
              </CardContent>
            </Card>

            <Card className="border-border/60 bg-card/60 backdrop-blur-sm">
              <CardContent className="p-3.5">
                <span className="text-[10px] uppercase font-bold text-emerald-600 dark:text-emerald-400 tracking-wider block">
                  Allowed Flows
                </span>
                <p className="text-2xl font-black text-emerald-600 dark:text-emerald-400 mt-1">
                  {result.connectionStats.allowed}
                </p>
                <p className="text-[10px] text-muted-foreground">Legitimate traffic</p>
              </CardContent>
            </Card>

            <Card className="border-border/60 bg-card/60 backdrop-blur-sm">
              <CardContent className="p-3.5">
                <span className="text-[10px] uppercase font-bold text-rose-600 dark:text-rose-400 tracking-wider block">
                  Blocked / Filtered
                </span>
                <p className="text-2xl font-black text-rose-600 dark:text-rose-400 mt-1">
                  {result.connectionStats.blocked}
                </p>
                <p className="text-[10px] text-muted-foreground">Firewall drops</p>
              </CardContent>
            </Card>

            <Card className="border-border/60 bg-card/60 backdrop-blur-sm">
              <CardContent className="p-3.5">
                <span className="text-[10px] uppercase font-bold text-amber-600 dark:text-amber-400 tracking-wider block">
                  Suspicious Activity
                </span>
                <p className="text-2xl font-black text-amber-600 dark:text-amber-400 mt-1">
                  {result.connectionStats.suspicious}
                </p>
                <p className="text-[10px] text-muted-foreground">Unusual ports/flows</p>
              </CardContent>
            </Card>

            <Card className="border-border/60 bg-card/60 backdrop-blur-sm">
              <CardContent className="p-3.5">
                <span className="text-[10px] uppercase font-bold text-muted-foreground tracking-wider block">
                  Risk Level
                </span>
                <div className="flex items-baseline gap-2 mt-1">
                  <p className={`text-2xl font-black ${riskGlow}`}>{result.riskScore}</p>
                  <span className="text-xs font-bold text-muted-foreground">/ 100</span>
                </div>
                <Badge
                  variant={result.alert ? "destructive" : "secondary"}
                  className="mt-1 text-[10px] px-1.5 py-0 h-4 uppercase"
                >
                  {result.status}
                </Badge>
              </CardContent>
            </Card>
          </div>
        )}

        {/* Protocol Filter Badges */}
        {result?.protocols && Object.keys(result.protocols).length > 0 && (
          <div className="flex flex-wrap items-center gap-2 p-2.5 rounded-lg border border-border/50 bg-muted/20 text-xs">
            <span className="font-semibold text-muted-foreground flex items-center gap-1.5">
              <Activity className="h-3.5 w-3.5 text-cyan-500" /> Protocols:
            </span>
            <Button
              size="sm"
              variant={protocolFilter === "ALL" ? "default" : "outline"}
              onClick={() => setProtocolFilter("ALL")}
              className="h-6 text-[11px] px-2"
            >
              ALL ({result.connectionStats.totalConnections})
            </Button>
            {Object.entries(result.protocols).map(([proto, count]) => (
              <Button
                key={proto}
                size="sm"
                variant={protocolFilter === proto ? "default" : "outline"}
                onClick={() => setProtocolFilter(proto)}
                className="h-6 text-[11px] px-2 font-mono"
              >
                {proto} ({count})
              </Button>
            ))}
          </div>
        )}

        {/* Filter Bar */}
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-border/50 bg-card/50 p-3">
          <div className="relative flex-1 min-w-[240px] max-w-md">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search by IP, port, service (HTTPS, SSH, C2), process..."
              value={searchFilter}
              onChange={(e) => setSearchFilter(e.target.value)}
              className="pl-9 text-xs h-9 bg-background/60"
            />
          </div>

          <div className="flex items-center gap-2">
            <Button
              size="sm"
              variant={statusFilter === "ALL" ? "default" : "outline"}
              onClick={() => setStatusFilter("ALL")}
              className="text-xs h-8"
            >
              All Flows
            </Button>
            <Button
              size="sm"
              variant={statusFilter === "SUSPICIOUS" ? "default" : "outline"}
              onClick={() => setStatusFilter("SUSPICIOUS")}
              className="text-xs h-8 text-amber-600 gap-1.5"
            >
              <span className="h-2 w-2 rounded-full bg-amber-500" />
              Suspicious Only
            </Button>
            <Button
              size="sm"
              variant={statusFilter === "BLOCKED" ? "default" : "outline"}
              onClick={() => setStatusFilter("BLOCKED")}
              className="text-xs h-8 text-rose-600 gap-1.5"
            >
              <span className="h-2 w-2 rounded-full bg-rose-500" />
              Blocked
            </Button>
          </div>
        </div>

        {/* Main Content: Connections Table & AI SOC Intelligence */}
        <div className="grid grid-cols-1 gap-6 xl:grid-cols-[1.3fr_0.7fr]">
          {/* Active Network Flows Table */}
          <Card className="border-border/70 bg-card/60 backdrop-blur-sm">
            <CardHeader className="p-4 pb-2 border-b border-border/40">
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-base font-bold flex items-center gap-2">
                    <Activity className="h-4 w-4 text-cyan-500" /> Live Network Connections ({filteredConnections.length})
                  </CardTitle>
                  <CardDescription className="text-xs">
                    Inbound and outbound flows correlated with endpoint processes and threat signatures.
                  </CardDescription>
                </div>
                {autoScanEnabled && (
                  <Badge className="gap-1.5 bg-emerald-500/10 text-emerald-600 border-emerald-500/30 text-[10px]">
                    <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" /> LIVE STREAM
                  </Badge>
                )}
              </div>
            </CardHeader>
            <CardContent className="p-0">
              <div className="max-h-[560px] overflow-y-auto">
                <table className="w-full text-left text-xs">
                  <thead className="sticky top-0 bg-muted/90 backdrop-blur-sm text-muted-foreground border-b z-10">
                    <tr>
                      <th className="p-2.5">Time</th>
                      <th className="p-2.5">Source IP</th>
                      <th className="p-2.5">Destination & Service</th>
                      <th className="p-2.5">Protocol</th>
                      <th className="p-2.5">Process</th>
                      <th className="p-2.5">Status</th>
                      <th className="p-2.5 text-right">SOC Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/60">
                    {filteredConnections.length > 0 ? (
                      filteredConnections.map((conn, idx) => {
                        const isSuspicious = conn.threatStatus !== "normal";
                        return (
                          <tr
                            key={`${conn.timestamp}-${idx}`}
                            className={`hover:bg-muted/40 transition-colors ${
                              isSuspicious ? "bg-amber-500/[0.04] dark:bg-amber-500/[0.08]" : ""
                            }`}
                          >
                            <td className="p-2.5 font-mono text-[11px] whitespace-nowrap text-muted-foreground">
                              {conn.timestamp ? new Date(conn.timestamp).toLocaleTimeString() : "-"}
                            </td>
                            <td className="p-2.5 font-mono">
                              <div>
                                <span className="font-semibold">{conn.sourceIp}</span>
                                {conn.hostname && (
                                  <span className="block text-[10px] text-muted-foreground font-sans">
                                    {conn.hostname}
                                  </span>
                                )}
                              </div>
                            </td>
                            <td className="p-2.5 font-mono">
                              <div className="flex items-center gap-1.5">
                                <span className="font-semibold text-foreground">
                                  {conn.destinationIp}:{conn.destinationPort}
                                </span>
                                {conn.service && (
                                  <Badge
                                    variant="outline"
                                    className={`text-[9px] font-sans px-1 py-0 ${
                                      conn.service.includes("C2")
                                        ? "border-rose-500 text-rose-500 font-bold animate-pulse"
                                        : "border-border"
                                    }`}
                                  >
                                    {conn.service}
                                  </Badge>
                                )}
                              </div>
                            </td>
                            <td className="p-2.5">
                              <Badge variant="outline" className="text-[10px] uppercase font-mono px-1.5 py-0">
                                {conn.protocol}
                              </Badge>
                            </td>
                            <td className="p-2.5 font-mono text-cyan-600 dark:text-cyan-400">
                              {conn.processName || "svchost.exe"}
                            </td>
                            <td className="p-2.5">
                              <Badge
                                variant={
                                  conn.action === "BLOCK"
                                    ? "destructive"
                                    : isSuspicious
                                    ? "secondary"
                                    : "default"
                                }
                                className="text-[10px] capitalize px-1.5 py-0"
                              >
                                {conn.action === "BLOCK"
                                  ? "Blocked"
                                  : isSuspicious
                                  ? "Suspicious C2"
                                  : "Allowed"}
                              </Badge>
                            </td>
                            <td className="p-2.5 text-right">
                              <div className="flex justify-end gap-1">
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  className="h-6 px-1.5 text-[10px] text-muted-foreground hover:text-cyan-500"
                                  title="Investigate with SOC Copilot"
                                  onClick={() => setLocation("/copilot")}
                                >
                                  Copilot
                                </Button>
                                {isSuspicious && (
                                  <Button
                                    variant="destructive"
                                    size="sm"
                                    className="h-6 px-2 text-[10px] gap-1"
                                    onClick={() => toast.success(`Simulated firewall block for IP ${conn.destinationIp}`)}
                                  >
                                    <Lock className="h-3 w-3" /> Block IP
                                  </Button>
                                )}
                              </div>
                            </td>
                          </tr>
                        );
                      })
                    ) : (
                      <tr>
                        <td colSpan={7} className="p-8 text-center text-muted-foreground text-xs">
                          {isLoading ? "Capturing packets and telemetry..." : "No connections matching active filter criteria."}
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>

          {/* AI SOC Threat Intelligence & Response Checklist */}
          <div className="space-y-4">
            {/* AI Security Reasoning */}
            <Card className="border-border/70 bg-card/60 backdrop-blur-sm">
              <CardHeader className="p-4 pb-2">
                <CardTitle className="text-base font-bold flex items-center gap-2">
                  <ShieldCheck className="h-4 w-4 text-emerald-500" /> AI SOC Security Analysis
                </CardTitle>
                <CardDescription className="text-xs">
                  Automated reasoning powered by {result?.source === "gemini" ? "Google Gemini" : "Heuristic Rule Engine"}
                </CardDescription>
              </CardHeader>
              <CardContent className="p-4 pt-2 space-y-3">
                <div className="rounded-lg border border-border bg-muted/30 p-3 text-xs leading-relaxed text-foreground">
                  {result?.reasoning || "Initiate a live capture to analyze network flow anomalies and host behavior."}
                </div>

                {/* Detected Vulnerabilities */}
                <div className="space-y-1.5">
                  <span className="text-[10px] uppercase font-bold text-muted-foreground tracking-wider">
                    Detected Indicators
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {result?.vulnerabilities && result.vulnerabilities.length > 0 ? (
                      result.vulnerabilities.map((vuln, i) => (
                        <Badge key={i} variant="destructive" className="text-[11px] gap-1 py-0.5">
                          <AlertTriangle className="h-3 w-3" /> {vuln}
                        </Badge>
                      ))
                    ) : (
                      <span className="text-xs text-muted-foreground">No active vulnerabilities identified in current stream.</span>
                    )}
                  </div>
                </div>

                {/* Response Action Checklist */}
                <div className="space-y-2 pt-2 border-t border-border/40">
                  <span className="text-[10px] uppercase font-bold text-muted-foreground tracking-wider block">
                    SOC Mitigation Checklist
                  </span>
                  <div className="space-y-1.5">
                    {result?.remediationSteps && result.remediationSteps.length > 0 ? (
                      result.remediationSteps.map((step, idx) => {
                        const isDone = Boolean(completedRemediations[idx]);
                        return (
                          <div
                            key={idx}
                            onClick={() => toggleRemediation(idx)}
                            className={`flex items-start gap-2.5 rounded-lg border p-2.5 text-xs cursor-pointer transition-colors ${
                              isDone
                                ? "border-emerald-500/30 bg-emerald-500/5 text-muted-foreground line-through"
                                : "border-border/60 hover:bg-muted/40"
                            }`}
                          >
                            <div className="mt-0.5">
                              {isDone ? (
                                <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                              ) : (
                                <div className="h-4 w-4 rounded border border-muted-foreground" />
                              )}
                            </div>
                            <span className="flex-1">{step}</span>
                          </div>
                        );
                      })
                    ) : (
                      <span className="text-xs text-muted-foreground">Normal traffic parameters; continue routine monitoring.</span>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Raw Snapshot Inspector */}
            <Card className="border-border/70 bg-card/60 backdrop-blur-sm">
              <CardHeader className="p-4 pb-2">
                <CardTitle className="text-sm font-bold flex items-center gap-2">
                  <Terminal className="h-4 w-4 text-cyan-500" /> Raw Telemetry & Socket Preview
                </CardTitle>
              </CardHeader>
              <CardContent className="p-4 pt-1">
                <pre className="max-h-[160px] overflow-y-auto rounded bg-background p-2.5 font-mono text-[10px] text-muted-foreground leading-snug">
                  {result?.snapshotPreview || "No snapshot available"}
                </pre>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}
