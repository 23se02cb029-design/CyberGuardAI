import { useState, useMemo } from "react";
import DashboardLayout from "@/components/DashboardLayout";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { trpc } from "@/lib/trpc";
import { getRiskProfile } from "@/lib/risk";
import { useTheme } from "@/contexts/ThemeContext";
import {
  Activity,
  AlertTriangle,
  Check,
  Copy,
  Cpu,
  Download,
  ExternalLink,
  Flame,
  Globe,
  HardDrive,
  Laptop,
  Lock,
  Play,
  Plus,
  Radio,
  RefreshCw,
  Search,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  SlidersHorizontal,
  Terminal,
  Trash2,
  Unlock,
  Wifi,
  Zap,
} from "lucide-react";
import { toast } from "sonner";
import { Link } from "wouter";

export default function Endpoints() {
  const { theme } = useTheme();
  const isDark = theme === "dark";

  // State for Enrollment Modal
  const [enrollModalOpen, setEnrollModalOpen] = useState(false);
  const [name, setName] = useState("FIN-WORKSTATION-01");
  const [hostname, setHostname] = useState("FIN-PC01.corp.local");
  const [os, setOs] = useState("Windows 11 Enterprise");
  const [agentVersion, setAgentVersion] = useState("1.2.4");
  const [createdEndpoint, setCreatedEndpoint] = useState<null | {
    endpointId: number;
    token: string;
    endpointName: string;
    expiresAt?: string;
    status: string;
  }>(null);
  const [copiedToken, setCopiedToken] = useState(false);
  const [copiedScript, setCopiedScript] = useState<string | null>(null);

  // Search & Filter State
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<"all" | "online" | "warning" | "revoked">("all");

  // Selected Endpoint for Deep Inspection Drawer/Dialog
  const [selectedEndpointId, setSelectedEndpointId] = useState<number | null>(null);
  const [inspectModalOpen, setInspectModalOpen] = useState(false);

  // tRPC queries & mutations
  const endpointsQuery = trpc.endpoints.list.useQuery(undefined, { refetchInterval: 8000 });
  const telemetryQuery = trpc.endpoints.getTelemetry.useQuery(
    selectedEndpointId ? { endpointId: selectedEndpointId, limit: 30 } : undefined,
    { enabled: Boolean(selectedEndpointId), refetchInterval: 5000 }
  );

  const createMutation = trpc.endpoints.create.useMutation({
    onSuccess: (data) => {
      setCreatedEndpoint(data);
      toast.success(`Enrollment token generated for ${data.endpointName}`);
      void endpointsQuery.refetch();
    },
    onError: (err) => toast.error(err.message || "Failed to generate enrollment token"),
  });

  const revokeMutation = trpc.endpoints.revoke.useMutation({
    onSuccess: () => {
      toast.success("Endpoint revoked successfully");
      void endpointsQuery.refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const isolateMutation = trpc.endpoints.isolate.useMutation({
    onSuccess: (data) => {
      toast.success(data.message);
      void endpointsQuery.refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const quickScanMutation = trpc.endpoints.quickScan.useMutation({
    onSuccess: (data) => {
      toast.success(data.message);
      void endpointsQuery.refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const simulateMutation = trpc.endpoints.simulateTelemetry.useMutation({
    onSuccess: (data) => {
      toast.success(`Injected telemetry: Risk Score ${data.riskScore} (${data.severity})`);
      void endpointsQuery.refetch();
      if (selectedEndpointId) void telemetryQuery.refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const seedFleetMutation = trpc.endpoints.seedFleet.useMutation({
    onSuccess: (data) => {
      toast.success(`Seeded ${data.count} enterprise workstations into SOC fleet!`);
      void endpointsQuery.refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const deleteMutation = trpc.endpoints.delete.useMutation({
    onSuccess: () => {
      toast.success("Endpoint removed from inventory");
      setInspectModalOpen(false);
      void endpointsQuery.refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  // Derived Fleet Stats
  const endpointsList = endpointsQuery.data || [];
  const totalCount = endpointsList.length;
  const onlineCount = endpointsList.filter((e) => e.status === "online").length;
  const warningCount = endpointsList.filter((e) => e.status === "warning").length;
  const revokedCount = endpointsList.filter((e) => e.status === "revoked").length;

  // Filtered Endpoints
  const filteredEndpoints = useMemo(() => {
    return endpointsList.filter((e) => {
      const matchesSearch =
        !searchQuery ||
        e.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (e.hostname && e.hostname.toLowerCase().includes(searchQuery.toLowerCase())) ||
        (e.os && e.os.toLowerCase().includes(searchQuery.toLowerCase()));

      const matchesStatus =
        statusFilter === "all" ||
        (statusFilter === "online" && e.status === "online") ||
        (statusFilter === "warning" && e.status === "warning") ||
        (statusFilter === "revoked" && e.status === "revoked");

      return matchesSearch && matchesStatus;
    });
  }, [endpointsList, searchQuery, statusFilter]);

  const selectedEndpoint = endpointsList.find((e) => e.id === selectedEndpointId);

  // Helper for copying scripts
  const handleCopy = (text: string, type: string) => {
    navigator.clipboard.writeText(text);
    if (type === "token") {
      setCopiedToken(true);
      setTimeout(() => setCopiedToken(false), 2000);
    } else {
      setCopiedScript(type);
      setTimeout(() => setCopiedScript(null), 2000);
    }
    toast.success("Copied to clipboard!");
  };

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Header Bar */}
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border/40 pb-5">
          <div>
            <div className="flex items-center gap-2 text-cyan-600 dark:text-cyan-400">
              <Shield className="h-5 w-5 animate-pulse" />
              <span className="text-xs font-bold uppercase tracking-widest">Enterprise EDR // Fleet Control</span>
            </div>
            <h1 className="mt-1 text-3xl font-black tracking-tight">Endpoint Fleet Management</h1>
            <p className="text-xs text-muted-foreground mt-0.5">
              Live telemetry, real-time socket inspection, and instant host containment for all corporate PCs.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => seedFleetMutation.mutate()}
              disabled={seedFleetMutation.isPending}
              className="gap-2 border-cyan-500/30 text-cyan-700 dark:text-cyan-300 hover:bg-cyan-500/10"
            >
              <RefreshCw className={`h-4 w-4 ${seedFleetMutation.isPending ? "animate-spin" : ""}`} />
              Simulate PC Fleet
            </Button>

            <Button
              size="sm"
              onClick={() => setEnrollModalOpen(true)}
              className="gap-2 bg-gradient-to-r from-cyan-600 to-blue-600 font-semibold text-white shadow-lg hover:from-cyan-500 hover:to-blue-500"
            >
              <Plus className="h-4 w-4" />
              Enroll Workstation
            </Button>

            <Badge className="gap-2 border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400">
              <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" /> SOC Fleet Online
            </Badge>
          </div>
        </div>

        {/* Fleet KPI Metric Cards */}
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <Card className="border-border/60 bg-card/60 backdrop-blur-sm">
            <CardContent className="p-4 flex items-center justify-between">
              <div>
                <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Total Workstations</p>
                <p className="mt-1 text-2xl font-black">{totalCount}</p>
                <p className="text-[11px] text-muted-foreground">Monitored corporate hosts</p>
              </div>
              <div className="rounded-xl border border-cyan-500/30 bg-cyan-500/10 p-3 text-cyan-600 dark:text-cyan-400">
                <Laptop className="h-6 w-6" />
              </div>
            </CardContent>
          </Card>

          <Card className="border-border/60 bg-card/60 backdrop-blur-sm">
            <CardContent className="p-4 flex items-center justify-between">
              <div>
                <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Online & Healthy</p>
                <p className="mt-1 text-2xl font-black text-emerald-600 dark:text-emerald-400">{onlineCount}</p>
                <p className="text-[11px] text-emerald-600/80">Active heartbeat streaming</p>
              </div>
              <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-3 text-emerald-600 dark:text-emerald-400">
                <ShieldCheck className="h-6 w-6" />
              </div>
            </CardContent>
          </Card>

          <Card className="border-border/60 bg-card/60 backdrop-blur-sm">
            <CardContent className="p-4 flex items-center justify-between">
              <div>
                <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Warning / High Risk</p>
                <p className="mt-1 text-2xl font-black text-amber-600 dark:text-amber-400">{warningCount}</p>
                <p className="text-[11px] text-amber-600/80">Requires SOC analyst review</p>
              </div>
              <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-3 text-amber-600 dark:text-amber-400">
                <ShieldAlert className="h-6 w-6" />
              </div>
            </CardContent>
          </Card>

          <Card className="border-border/60 bg-card/60 backdrop-blur-sm">
            <CardContent className="p-4 flex items-center justify-between">
              <div>
                <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Quarantined / Revoked</p>
                <p className="mt-1 text-2xl font-black text-rose-600 dark:text-rose-400">{revokedCount}</p>
                <p className="text-[11px] text-rose-600/80">Isolated from corporate LAN</p>
              </div>
              <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-3 text-rose-600 dark:text-rose-400">
                <ShieldX className="h-6 w-6" />
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Search, Filter Tabs & Fast Control */}
        <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-border/50 bg-card/40 p-3 backdrop-blur-sm">
          <div className="flex flex-1 items-center gap-2 min-w-[260px] max-w-md">
            <div className="relative w-full">
              <Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search workstations by name, hostname, OS..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9 bg-background/50 text-sm"
              />
            </div>
            {searchQuery && (
              <Button variant="ghost" size="sm" onClick={() => setSearchQuery("")} className="h-9 px-2 text-xs">
                Clear
              </Button>
            )}
          </div>

          <div className="flex items-center gap-1.5 overflow-x-auto">
            <Button
              variant={statusFilter === "all" ? "default" : "outline"}
              size="sm"
              onClick={() => setStatusFilter("all")}
              className="text-xs h-8"
            >
              All ({totalCount})
            </Button>
            <Button
              variant={statusFilter === "online" ? "default" : "outline"}
              size="sm"
              onClick={() => setStatusFilter("online")}
              className="text-xs h-8 gap-1.5"
            >
              <span className="h-2 w-2 rounded-full bg-emerald-500" />
              Online ({onlineCount})
            </Button>
            <Button
              variant={statusFilter === "warning" ? "default" : "outline"}
              size="sm"
              onClick={() => setStatusFilter("warning")}
              className="text-xs h-8 gap-1.5"
            >
              <span className="h-2 w-2 rounded-full bg-amber-500" />
              Warning ({warningCount})
            </Button>
            <Button
              variant={statusFilter === "revoked" ? "default" : "outline"}
              size="sm"
              onClick={() => setStatusFilter("revoked")}
              className="text-xs h-8 gap-1.5"
            >
              <span className="h-2 w-2 rounded-full bg-rose-500" />
              Quarantined ({revokedCount})
            </Button>
          </div>
        </div>

        {/* Endpoints Grid List */}
        {endpointsQuery.isLoading ? (
          <div className="flex min-h-[300px] flex-col items-center justify-center gap-3 rounded-xl border border-dashed p-10 text-center">
            <RefreshCw className="h-8 w-8 animate-spin text-cyan-500" />
            <p className="text-sm font-medium text-muted-foreground">Scanning and syncing endpoint fleet...</p>
          </div>
        ) : filteredEndpoints.length === 0 ? (
          <div className="flex min-h-[300px] flex-col items-center justify-center gap-4 rounded-xl border border-dashed border-border/80 p-12 text-center bg-card/20">
            <div className="rounded-full bg-cyan-500/10 p-4 text-cyan-600 dark:text-cyan-400">
              <Laptop className="h-10 w-10" />
            </div>
            <div>
              <p className="text-lg font-bold">No workstations matching query</p>
              <p className="text-sm text-muted-foreground mt-1 max-w-md">
                {searchQuery
                  ? "Try clearing your search filters to find registered endpoints."
                  : "Your endpoint inventory is currently empty. Click 'Simulate PC Fleet' or enroll a new PC to begin monitoring."}
              </p>
            </div>
            <div className="flex gap-3">
              <Button
                variant="outline"
                size="sm"
                onClick={() => seedFleetMutation.mutate()}
                disabled={seedFleetMutation.isPending}
                className="gap-2"
              >
                <RefreshCw className="h-4 w-4" /> Simulate Enterprise Fleet
              </Button>
              <Button size="sm" onClick={() => setEnrollModalOpen(true)} className="gap-2">
                <Plus className="h-4 w-4" /> Enroll First Workstation
              </Button>
            </div>
          </div>
        ) : (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {filteredEndpoints.map((endpoint) => {
              const isWarning = endpoint.status === "warning";
              const isRevoked = endpoint.status === "revoked";
              const isOnline = endpoint.status === "online";
              const riskScore = isWarning ? 78 : isRevoked ? 95 : 12;
              const riskProfile = getRiskProfile(riskScore);

              return (
                <Card
                  key={endpoint.id}
                  className={`group relative overflow-hidden transition-all duration-200 hover:shadow-lg ${
                    isWarning
                      ? "border-amber-500/50 bg-amber-500/[0.03]"
                      : isRevoked
                      ? "border-rose-500/50 bg-rose-500/[0.03]"
                      : "border-border/70 hover:border-cyan-500/50"
                  }`}
                >
                  <CardHeader className="p-4 pb-2">
                    <div className="flex items-start justify-between gap-3">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <Laptop className={`h-5 w-5 ${isWarning ? "text-amber-500" : isRevoked ? "text-rose-500" : "text-cyan-500"}`} />
                          <h3 className="font-bold text-base leading-tight tracking-tight group-hover:text-cyan-500 transition-colors">
                            {endpoint.name}
                          </h3>
                        </div>
                        <p className="text-xs font-mono text-muted-foreground break-all">
                          {endpoint.hostname || "hostname-unspecified"}
                        </p>
                      </div>

                      <Badge
                        variant={isOnline ? "default" : isWarning ? "secondary" : isRevoked ? "destructive" : "outline"}
                        className="capitalize gap-1.5 text-xs font-semibold px-2 py-0.5"
                      >
                        <span
                          className={`h-1.5 w-1.5 rounded-full ${
                            isOnline ? "bg-emerald-400 animate-pulse" : isWarning ? "bg-amber-400 animate-ping" : "bg-rose-400"
                          }`}
                        />
                        {endpoint.status}
                      </Badge>
                    </div>
                  </CardHeader>

                  <CardContent className="p-4 pt-2 space-y-3">
                    <div className="grid grid-cols-3 gap-2 rounded-lg bg-muted/40 p-2.5 text-xs">
                      <div>
                        <span className="block text-[10px] uppercase font-bold tracking-wider text-muted-foreground">OS</span>
                        <span className="font-medium truncate block" title={endpoint.os || "Unknown"}>
                          {endpoint.os ? endpoint.os.split(" ")[0] : "Windows"}
                        </span>
                      </div>
                      <div>
                        <span className="block text-[10px] uppercase font-bold tracking-wider text-muted-foreground">Agent</span>
                        <span className="font-medium font-mono truncate block">v{endpoint.agentVersion || "1.0"}</span>
                      </div>
                      <div>
                        <span className="block text-[10px] uppercase font-bold tracking-wider text-muted-foreground">Host Risk</span>
                        <span className={`font-bold ${isDark ? riskProfile.glowDark : riskProfile.glowLight}`}>
                          {riskScore}/100
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center justify-between text-[11px] text-muted-foreground px-1">
                      <span className="flex items-center gap-1">
                        <Activity className="h-3.5 w-3.5 text-cyan-500" />
                        Heartbeat: {endpoint.lastSeen ? "Active" : "Pending"}
                      </span>
                      <span>Enrolled: {endpoint.enrolledAt ? new Date(endpoint.enrolledAt).toLocaleDateString() : "Recent"}</span>
                    </div>

                    {/* Action Toolbar */}
                    <div className="flex flex-wrap gap-2 pt-1 border-t border-border/40">
                      <Link href={`/network?endpointId=${endpoint.id}`} className="flex-1">
                        <Button
                          size="sm"
                          className="w-full gap-1 text-xs h-8 font-semibold bg-cyan-600 hover:bg-cyan-500 text-white shadow-xs"
                          title="Monitor this employee's real-time traffic"
                        >
                          <Activity className="h-3.5 w-3.5" /> Monitor Traffic
                        </Button>
                      </Link>

                      <Button
                        size="sm"
                        variant="outline"
                        className="gap-1 text-xs h-8 font-medium border-border"
                        onClick={() => {
                          setSelectedEndpointId(endpoint.id);
                          setInspectModalOpen(true);
                        }}
                      >
                        <Terminal className="h-3.5 w-3.5" /> Inspect
                      </Button>

                      {isRevoked ? (
                        <Button
                          size="sm"
                          variant="outline"
                          className="text-xs h-8 gap-1 border-emerald-500/40 text-emerald-600 hover:bg-emerald-500/10"
                          onClick={() => isolateMutation.mutate({ id: endpoint.id, isolate: false })}
                          disabled={isolateMutation.isPending}
                        >
                          <Unlock className="h-3.5 w-3.5" /> Restore
                        </Button>
                      ) : (
                        <Button
                          size="sm"
                          variant="outline"
                          className="text-xs h-8 gap-1 border-rose-500/40 text-rose-600 hover:bg-rose-500/10"
                          onClick={() => isolateMutation.mutate({ id: endpoint.id, isolate: true })}
                          disabled={isolateMutation.isPending}
                          title="Isolate host from corporate LAN"
                        >
                          <Lock className="h-3.5 w-3.5" /> Isolate
                        </Button>
                      )}

                      <Button
                        size="sm"
                        variant="ghost"
                        className="h-8 w-8 p-0 text-muted-foreground hover:text-amber-500"
                        title="Inject Test Signal"
                        onClick={() =>
                          simulateMutation.mutate({
                            endpointId: endpoint.id,
                            type: isWarning ? "normal" : "suspicious_beacon",
                          })
                        }
                        disabled={simulateMutation.isPending}
                      >
                        <Zap className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        )}

        {/* Enrollment Modal */}
        <Dialog open={enrollModalOpen} onOpenChange={setEnrollModalOpen}>
          <DialogContent className="max-w-lg">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <Laptop className="h-5 w-5 text-cyan-600 dark:text-cyan-400" />
                Register New Enterprise Workstation
              </DialogTitle>
              <DialogDescription>
                Generate an authorized endpoint enrollment token and copy the 1-line agent deploy script.
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-4 py-2">
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold">Endpoint Name</label>
                  <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. SOC-STATION-01" />
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold">Hostname / FQDN</label>
                  <Input value={hostname} onChange={(e) => setHostname(e.target.value)} placeholder="e.g. pc01.corp.local" />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold">Operating System</label>
                  <Input value={os} onChange={(e) => setOs(e.target.value)} placeholder="e.g. Windows 11 Enterprise" />
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold">Agent Version</label>
                  <Input value={agentVersion} onChange={(e) => setAgentVersion(e.target.value)} />
                </div>
              </div>

              <Button
                className="w-full bg-cyan-600 hover:bg-cyan-500 font-semibold text-white"
                onClick={() => createMutation.mutate({ name, hostname, os, agentVersion })}
                disabled={createMutation.isPending}
              >
                {createMutation.isPending ? "Generating Token..." : "Generate Enrollment Token"}
              </Button>

              {createdEndpoint && (
                <div className="space-y-3 rounded-lg border border-amber-500/30 bg-amber-500/5 p-3.5 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-amber-700 dark:text-amber-300">Enrollment Secret Token</span>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleCopy(createdEndpoint.token, "token")}
                      className="h-6 px-2 text-[11px] gap-1"
                    >
                      {copiedToken ? <Check className="h-3 w-3 text-emerald-500" /> : <Copy className="h-3 w-3" />}
                      Copy Token
                    </Button>
                  </div>
                  <code className="block break-all rounded bg-background p-2 font-mono text-[11px] text-foreground">
                    {createdEndpoint.token}
                  </code>

                  <div className="mt-2 space-y-1 text-muted-foreground">
                    <p className="font-semibold text-foreground text-[11px]">Instant Deploy Command (PowerShell / Windows):</p>
                    <div className="flex items-center gap-2">
                      <code className="block flex-1 break-all rounded bg-background p-1.5 font-mono text-[10px] text-cyan-600 dark:text-cyan-400">
                        npm run start:agent -- --endpointId={createdEndpoint.endpointId} --token={createdEndpoint.token}
                      </code>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() =>
                          handleCopy(
                            `npm run start:agent -- --endpointId=${createdEndpoint.endpointId} --token=${createdEndpoint.token}`,
                            "powershell"
                          )
                        }
                        className="h-7 text-xs"
                      >
                        {copiedScript === "powershell" ? <Check className="h-3 w-3 text-emerald-500" /> : <Copy className="h-3 w-3" />}
                      </Button>
                    </div>
                  </div>
                </div>
              )}
            </div>

            <DialogFooter>
              <Button variant="outline" onClick={() => setEnrollModalOpen(false)}>
                Done
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Deep Endpoint Inspection Dialog / Drawer */}
        <Dialog open={inspectModalOpen} onOpenChange={setInspectModalOpen}>
          <DialogContent className="max-w-4xl max-h-[85vh] overflow-y-auto">
            {selectedEndpoint ? (
              <div className="space-y-5">
                <DialogHeader className="border-b border-border/40 pb-4">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div className="flex items-center gap-3">
                      <div className="rounded-xl bg-cyan-500/10 p-2.5 text-cyan-600 dark:text-cyan-400">
                        <Laptop className="h-6 w-6" />
                      </div>
                      <div>
                        <DialogTitle className="text-xl font-bold flex items-center gap-2">
                          {selectedEndpoint.name}
                          <Badge
                            variant={
                              selectedEndpoint.status === "online"
                                ? "default"
                                : selectedEndpoint.status === "warning"
                                ? "secondary"
                                : "destructive"
                            }
                            className="text-xs"
                          >
                            {selectedEndpoint.status}
                          </Badge>
                        </DialogTitle>
                        <DialogDescription className="text-xs font-mono">
                          {selectedEndpoint.hostname || "unknown-host"} • {selectedEndpoint.os || "Windows 11"} • Agent v
                          {selectedEndpoint.agentVersion || "1.0"}
                        </DialogDescription>
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => quickScanMutation.mutate({ id: selectedEndpoint.id })}
                        disabled={quickScanMutation.isPending}
                        className="text-xs gap-1.5"
                      >
                        <RefreshCw className={`h-3.5 w-3.5 ${quickScanMutation.isPending ? "animate-spin" : ""}`} />
                        Run Diagnostic Scan
                      </Button>

                      {selectedEndpoint.status === "revoked" ? (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => isolateMutation.mutate({ id: selectedEndpoint.id, isolate: false })}
                          className="text-xs gap-1.5 border-emerald-500 text-emerald-600"
                        >
                          <Unlock className="h-3.5 w-3.5" /> Reconnect
                        </Button>
                      ) : (
                        <Button
                          size="sm"
                          variant="destructive"
                          onClick={() => isolateMutation.mutate({ id: selectedEndpoint.id, isolate: true })}
                          className="text-xs gap-1.5"
                        >
                          <Lock className="h-3.5 w-3.5" /> Isolate Host
                        </Button>
                      )}
                    </div>
                  </div>
                </DialogHeader>

                <Tabs defaultValue="connections" className="w-full">
                  <TabsList className="grid w-full grid-cols-4 text-xs">
                    <TabsTrigger value="connections">Active Sockets</TabsTrigger>
                    <TabsTrigger value="telemetry">Telemetry Feed</TabsTrigger>
                    <TabsTrigger value="security">Security Posture</TabsTrigger>
                    <TabsTrigger value="deployment">Agent CLI & Scripts</TabsTrigger>
                  </TabsList>

                  {/* Tab 1: Active Sockets & Connections */}
                  <TabsContent value="connections" className="space-y-4 pt-3">
                    <div className="flex items-center justify-between text-xs text-muted-foreground">
                      <span>Monitored outbound and inbound TCP/UDP flows for this workstation</span>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => telemetryQuery.refetch()}
                        className="h-7 text-xs gap-1 text-cyan-600"
                      >
                        <RefreshCw className={`h-3 w-3 ${telemetryQuery.isRefetching ? "animate-spin" : ""}`} /> Refresh
                      </Button>
                    </div>

                    <div className="rounded-lg border border-border overflow-x-auto">
                      <table className="w-full text-left text-xs">
                        <thead className="border-b bg-muted/50 text-muted-foreground">
                          <tr>
                            <th className="p-2.5">Timestamp</th>
                            <th className="p-2.5">Source IP</th>
                            <th className="p-2.5">Remote Destination</th>
                            <th className="p-2.5">Protocol</th>
                            <th className="p-2.5">Process</th>
                            <th className="p-2.5">Threat Status</th>
                            <th className="p-2.5">Risk Score</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-border/60">
                          {telemetryQuery.data && telemetryQuery.data.length > 0 ? (
                            telemetryQuery.data.map((row, idx) => {
                              const evtData = (row.eventData as Record<string, any>) || {};
                              const isThreat = Number(row.riskScore) >= 60;
                              return (
                                <tr key={row.id || idx} className="hover:bg-muted/30">
                                  <td className="p-2.5 font-mono text-[11px] whitespace-nowrap">
                                    {row.createdAt ? new Date(row.createdAt).toLocaleTimeString() : "-"}
                                  </td>
                                  <td className="p-2.5 font-mono">{row.sourceIp || "192.168.1.45"}</td>
                                  <td className="p-2.5 font-mono font-semibold">
                                    {row.destinationIp}:{evtData.destinationPort || "443"}
                                  </td>
                                  <td className="p-2.5">
                                    <Badge variant="outline" className="text-[10px] uppercase">
                                      {row.protocol || "TCP"}
                                    </Badge>
                                  </td>
                                  <td className="p-2.5 font-mono text-cyan-600 dark:text-cyan-400">
                                    {row.processName || evtData.process || "system"}
                                  </td>
                                  <td className="p-2.5">
                                    <Badge
                                      variant={isThreat ? "destructive" : "secondary"}
                                      className="text-[10px] capitalize"
                                    >
                                      {isThreat ? "Malicious / C2" : "Allowed"}
                                    </Badge>
                                  </td>
                                  <td className="p-2.5 font-bold font-mono">
                                    <span className={isThreat ? "text-rose-500" : "text-emerald-500"}>
                                      {Number(row.riskScore).toFixed(0)}/100
                                    </span>
                                  </td>
                                </tr>
                              );
                            })
                          ) : (
                            <tr>
                              <td colSpan={7} className="p-6 text-center text-muted-foreground">
                                No active telemetry recorded yet. Click "Inject Test Signal" below to simulate network flows.
                              </td>
                            </tr>
                          )}
                        </tbody>
                      </table>
                    </div>

                    <div className="flex gap-2 justify-end pt-2">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => simulateMutation.mutate({ endpointId: selectedEndpoint.id, type: "suspicious_beacon" })}
                        className="text-xs gap-1 text-amber-600 border-amber-500/40"
                      >
                        <AlertTriangle className="h-3.5 w-3.5" /> Inject C2 Beacon Flow
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => simulateMutation.mutate({ endpointId: selectedEndpoint.id, type: "normal" })}
                        className="text-xs gap-1 text-emerald-600 border-emerald-500/40"
                      >
                        <Check className="h-3.5 w-3.5" /> Inject Clean Flow
                      </Button>
                    </div>
                  </TabsContent>

                  {/* Tab 2: Telemetry Feed */}
                  <TabsContent value="telemetry" className="space-y-3 pt-3">
                    <div className="space-y-2 max-h-[380px] overflow-y-auto pr-2">
                      {telemetryQuery.data && telemetryQuery.data.length > 0 ? (
                        telemetryQuery.data.map((row) => (
                          <div key={row.id} className="rounded-lg border border-border p-3 text-xs bg-card/60">
                            <div className="flex items-center justify-between">
                              <span className="font-bold text-cyan-600 dark:text-cyan-400 uppercase font-mono">
                                [{row.eventType}]
                              </span>
                              <span className="text-muted-foreground font-mono text-[11px]">
                                {row.createdAt ? new Date(row.createdAt).toLocaleString() : ""}
                              </span>
                            </div>
                            <pre className="mt-2 rounded bg-background p-2 font-mono text-[10px] overflow-x-auto text-muted-foreground">
                              {JSON.stringify(row.eventData, null, 2)}
                            </pre>
                          </div>
                        ))
                      ) : (
                        <p className="p-4 text-center text-muted-foreground text-xs">No telemetry logs found.</p>
                      )}
                    </div>
                  </TabsContent>

                  {/* Tab 3: Security Posture */}
                  <TabsContent value="security" className="space-y-4 pt-3">
                    <div className="rounded-lg border border-border p-4 bg-muted/30 space-y-3">
                      <h4 className="font-bold text-sm flex items-center gap-2">
                        <Shield className="h-4 w-4 text-cyan-500" /> Host Defense Status
                      </h4>
                      <p className="text-xs text-muted-foreground leading-relaxed">
                        CyberGuard AI EDR agent continuously inspects process memory, network sockets, child process spawns, and
                        DNS queries on this workstation. Network isolation acts via local firewall rules and loopback redirection.
                      </p>
                      <div className="grid grid-cols-2 gap-3 text-xs">
                        <div className="rounded bg-background p-2.5">
                          <span className="text-muted-foreground block text-[10px] uppercase font-bold">Network Firewall State</span>
                          <span className="font-semibold text-emerald-500">Enforcing (Hardware + Software)</span>
                        </div>
                        <div className="rounded bg-background p-2.5">
                          <span className="text-muted-foreground block text-[10px] uppercase font-bold">Credential Guard</span>
                          <span className="font-semibold text-emerald-500">Active</span>
                        </div>
                      </div>
                    </div>

                    <div className="flex justify-between items-center pt-2">
                      <Button
                        variant="destructive"
                        size="sm"
                        className="text-xs gap-1.5"
                        onClick={() => deleteMutation.mutate({ id: selectedEndpoint.id })}
                        disabled={deleteMutation.isPending}
                      >
                        <Trash2 className="h-3.5 w-3.5" /> Remove Workstation from Inventory
                      </Button>
                    </div>
                  </TabsContent>

                  {/* Tab 4: Agent CLI & Scripts */}
                  <TabsContent value="deployment" className="space-y-3 pt-3">
                    <p className="text-xs text-muted-foreground">
                      Deploy or run the lightweight CyberGuard EDR agent on this target workstation using the commands below:
                    </p>

                    <div className="space-y-2">
                      <label className="text-xs font-semibold">Windows PowerShell (Administrator)</label>
                      <div className="flex items-center gap-2">
                        <code className="block flex-1 rounded bg-muted p-2 font-mono text-[11px] break-all">
                          npm run start:agent -- --endpointId={selectedEndpoint.id}
                        </code>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleCopy(`npm run start:agent -- --endpointId=${selectedEndpoint.id}`, "ps-cmd")}
                        >
                          <Copy className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </div>

                    <div className="space-y-2">
                      <label className="text-xs font-semibold">Linux / macOS (Bash / Terminal)</label>
                      <div className="flex items-center gap-2">
                        <code className="block flex-1 rounded bg-muted p-2 font-mono text-[11px] break-all">
                          CYBERGUARD_ENDPOINT_ID={selectedEndpoint.id} npm start
                        </code>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleCopy(`CYBERGUARD_ENDPOINT_ID=${selectedEndpoint.id} npm start`, "sh-cmd")}
                        >
                          <Copy className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </div>
                  </TabsContent>
                </Tabs>
              </div>
            ) : null}
          </DialogContent>
        </Dialog>
      </div>
    </DashboardLayout>
  );
}
