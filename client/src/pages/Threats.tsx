import { useEffect, useMemo, useState } from "react";
import DashboardLayout from "@/components/DashboardLayout";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useTheme } from "@/contexts/ThemeContext";
import { getRiskProfile } from "@/lib/risk";
import { trpc } from "@/lib/trpc";
import { AlertTriangle, Filter, Search, Shield, Terminal, Zap, Eye, ChevronRight, Trash2 } from "lucide-react";
import { useLocation } from "wouter";
import { toast } from "sonner";

const threatIcons: Record<string, React.ReactNode> = {
  phishing: <AlertTriangle className="h-5 w-5 text-orange-500" />,
  brute_force: <Zap className="h-5 w-5 text-red-500" />,
  malware: <Shield className="h-5 w-5 text-purple-500" />,
  lateral_movement: <Eye className="h-5 w-5 text-blue-500" />,
  data_exfiltration: <AlertTriangle className="h-5 w-5 text-red-600" />,
  privilege_escalation: <Zap className="h-5 w-5 text-orange-600" />,
  unknown: <Shield className="h-5 w-5 text-zinc-400" />,
};

export default function Threats() {
  const [, navigate] = useLocation();
  const { theme } = useTheme();
  const isDark = theme === "dark";
  const threatsQuery = trpc.threats.list.useQuery({ limit: 100, offset: 0 });
  const trpcUtils = trpc.useUtils();
  const removeThreatMutation = trpc.threats.remove.useMutation({
    onSuccess: () => {
      toast.success("Threat removed");
      void trpcUtils.threats.list.invalidate();
      void trpcUtils.dashboard.metrics.invalidate();
    },
    onError: (error) => toast.error(`Failed to remove threat: ${error.message}`),
  });
  const removeAllThreatsMutation = trpc.threats.removeAll.useMutation({
    onSuccess: () => {
      toast.success("All threats removed");
      void trpcUtils.threats.list.invalidate();
      void trpcUtils.dashboard.metrics.invalidate();
    },
    onError: (error) => toast.error(`Failed to remove threats: ${error.message}`),
  });
  const threats = threatsQuery.data ?? [];
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("all");
  const [status, setStatus] = useState("all");
  const filteredThreats = useMemo(() => threats.filter((threat) => {
    const matchesSearch = !search || `${threat.threatType} ${threat.description} ${JSON.stringify(threat.affectedAssets)}`.toLowerCase().includes(search.toLowerCase());
    const score = Number(threat.riskScore || 0);
    const matchesSeverity = severity === "all" || getRiskProfile(score).level.toLowerCase() === severity;
    const matchesStatus = status === "all" || threat.status === status;
    return matchesSearch && matchesSeverity && matchesStatus;
  }), [threats, search, severity, status]);

  useEffect(() => {
    if (threatsQuery.data) console.info(`[THREATS_UI_RECEIVED] count=${threatsQuery.data.length}`);
  }, [threatsQuery.data]);

  return (
    <DashboardLayout>
      <div className="-m-4">
        <div className="blueprint-grid min-h-[calc(100vh-2rem)] bg-background p-5 text-foreground sm:p-7">
          {/* Header */}
          <div className="mb-6 flex flex-wrap items-center justify-between gap-4 border-b border-cyan-400/10 pb-6">
            <div className="space-y-1">
              <div className="flex items-center gap-2 text-cyan-600 dark:text-cyan-400">
                <Terminal className="h-5 w-5" />
                <span className="tech-label text-cyan-300">CyberGuard AI // Threat Feed</span>
              </div>
              <h1 className="text-3xl font-black tracking-tighter text-slate-900 sm:text-4xl dark:text-white">
                Threat Overview
              </h1>
              <p className="text-sm text-slate-600 dark:text-muted-foreground">Evidence-backed incidents with analyst context</p>
            </div>
            <div className="flex items-center gap-2">
              <Badge className="gap-1.5 border-cyan-500/40 bg-cyan-500/10 text-cyan-700 dark:text-cyan-400">
                <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-pulse" />
                {filteredThreats.length} DETECTIONS
              </Badge>
              {threats.length > 0 && (
                <Button
                  variant="outline"
                  size="sm"
                  className="gap-1 text-red-600 hover:bg-red-500/10 hover:text-red-700"
                  disabled={removeAllThreatsMutation.isPending || removeThreatMutation.isPending}
                  onClick={() => {
                    if (window.confirm("Remove all threats and their recommendations? This cannot be undone.")) {
                      removeAllThreatsMutation.mutate();
                    }
                  }}
                >
                  <Trash2 className="h-3.5 w-3.5" />
                  {removeAllThreatsMutation.isPending ? "Removing..." : "Remove All"}
                </Button>
              )}
            </div>
          </div>

          <div className="mb-5 grid grid-cols-2 gap-3 md:grid-cols-5">{["all", "critical", "high", "medium", "low"].map((level) => <div key={level} className="soc-surface rounded-lg p-3"><p className="tech-label">{level === "all" ? "Total" : level}</p><p className="mt-1 text-2xl font-bold text-white">{level === "all" ? threats.length : threats.filter((threat) => getRiskProfile(Number(threat.riskScore || 0)).level.toLowerCase() === level).length}</p></div>)}</div>
          <div className="mb-5 flex flex-wrap gap-2"><div className="relative min-w-[220px] flex-1"><Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" /><input aria-label="Search threats" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search threats, IPs, evidence..." className="h-9 w-full rounded-lg border border-slate-700 bg-slate-900/80 pl-10 text-sm text-slate-200 outline-none focus:border-cyan-400/60" /></div><select aria-label="Filter by severity" value={severity} onChange={(event) => setSeverity(event.target.value)} className="h-9 rounded-lg border border-slate-700 bg-slate-900 px-3 text-sm text-slate-300"><option value="all">All severity</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select><select aria-label="Filter by status" value={status} onChange={(event) => setStatus(event.target.value)} className="h-9 rounded-lg border border-slate-700 bg-slate-900 px-3 text-sm text-slate-300"><option value="all">All status</option><option value="new">Detected</option><option value="investigating">Investigating</option><option value="confirmed">Confirmed</option><option value="resolved">Resolved</option></select><Filter className="m-2 h-4 w-4 text-cyan-300" /></div>

          {threatsQuery.isLoading ? (
            <div className="rounded-xl border border-zinc-200 bg-white py-16 text-center dark:border-cyan-500/30 dark:bg-zinc-900/60">
              <p className="text-lg font-semibold text-zinc-800 dark:text-zinc-200">Loading threats...</p>
            </div>
          ) : threatsQuery.isError ? (
            <div className="rounded-xl border border-red-200 bg-white py-16 text-center dark:border-red-500/30 dark:bg-zinc-900/60">
              <p className="text-lg font-semibold text-red-700 dark:text-red-400">Unable to load threats</p>
              <p className="tech-label mt-2 text-zinc-500">{threatsQuery.error.message}</p>
            </div>
          ) : filteredThreats.length === 0 ? (
            <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-zinc-200 bg-white py-16 text-center dark:border-cyan-500/30 dark:bg-zinc-900/60">
              <Shield className="h-10 w-10 text-emerald-500 opacity-60" />
              <p className="text-lg font-semibold text-zinc-800 dark:text-zinc-200">No threats detected</p>
              <p className="tech-label text-zinc-500 dark:text-zinc-600">Upload security logs to begin analysis</p>
            </div>
          ) : (
            <div className="space-y-3">
              {filteredThreats.map((threat) => {
                const score = threat.riskScore ? Number(threat.riskScore) : 0;
                const risk = getRiskProfile(score);
                const glow = isDark ? risk.glowDark : risk.glowLight;
                const mitreAttackIds = Array.isArray(threat.mitreAttackIds)
                  ? threat.mitreAttackIds.filter((id): id is string => typeof id === "string")
                  : [];
                const assets = (threat.affectedAssets || {}) as Record<string, unknown>;
                const evidence = Array.isArray(threat.indicators) ? threat.indicators.filter((item): item is string => typeof item === "string") : [];

                return (
                  <div
                    key={threat.id}
                    className={`group flex items-start justify-between gap-4 rounded-xl border bg-white p-5 backdrop-blur-sm transition-all duration-300 hover:border-cyan-500/50 dark:bg-zinc-900/60 ${risk.border}`}
                  >
                    <button
                      type="button"
                      className="flex min-w-0 flex-1 cursor-pointer items-start gap-4 text-left"
                      onClick={() => navigate(`/threats/${threat.id}`)}
                    >
                      <div className="mt-1">{threatIcons[threat.threatType || "unknown"]}</div>
                      <div className="flex-1">
                        <div className="mb-2 flex flex-wrap items-center gap-3">
                          <h3 className="text-lg font-bold capitalize text-zinc-900 dark:text-white">
                            {threat.threatType?.replace(/_/g, " ") || "Unknown Threat"}
                          </h3>
                          <Badge className={`gap-1.5 ${risk.badge}`}>
                            <span className="h-1.5 w-1.5 rounded-full bg-current animate-pulse" />
                            {risk.level}
                          </Badge>
                        </div>
                        <p className="mb-3 text-sm text-zinc-600 dark:text-zinc-400">
                          {threat.description || "No description available"}
                        </p>
                        <div className="mb-3 grid grid-cols-1 gap-1 text-xs text-zinc-500 sm:grid-cols-3">
                          <span>Confidence: {threat.confidence ? Number(threat.confidence).toFixed(0) : 0}%</span>
                          <span>Source: {String(assets.sourceIp || "Unavailable")}</span>
                          <span>Destination: {String(assets.destinationIp || "Unavailable")}</span>
                        </div>
                        {evidence.length > 0 && (
                          <pre className="max-h-24 overflow-auto whitespace-pre-wrap rounded border border-zinc-200 bg-zinc-50 p-2 text-[11px] text-zinc-600 dark:border-zinc-800 dark:bg-zinc-950 dark:text-zinc-400">
                            {evidence.join("\n")}
                          </pre>
                        )}
                        {mitreAttackIds.length > 0 && (
                          <div className="flex flex-wrap gap-1.5">
                            {mitreAttackIds.slice(0, 3).map((id) => (
                              <Badge
                                key={id}
                                variant="outline"
                                className="border-zinc-300 font-mono text-[10px] text-zinc-500 dark:border-zinc-700 dark:text-zinc-500"
                              >
                                {id}
                              </Badge>
                            ))}
                            {mitreAttackIds.length > 3 && (
                              <Badge
                                variant="outline"
                                className="border-zinc-300 font-mono text-[10px] text-zinc-500 dark:border-zinc-700 dark:text-zinc-500"
                              >
                                +{mitreAttackIds.length - 3}
                              </Badge>
                            )}
                          </div>
                        )}
                      </div>
                    </button>
                    <div className="flex flex-col items-end gap-1 text-right">
                      <div className={`text-3xl font-black ${glow}`}>{score.toFixed(0)}</div>
                      <p className="tech-label text-zinc-500 dark:text-zinc-600">Risk Score</p>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="mt-2 gap-1 text-cyan-700 hover:bg-cyan-500/10 hover:text-cyan-800 dark:text-cyan-400 dark:hover:bg-cyan-500/10 dark:hover:text-cyan-300"
                      >
                        View Details <ChevronRight className="h-3.5 w-3.5" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="gap-1 text-red-600 hover:bg-red-500/10 hover:text-red-700"
                        disabled={removeThreatMutation.isPending}
                        onClick={() => {
                          if (window.confirm("Remove this threat and its recommendations?")) {
                            removeThreatMutation.mutate({ id: threat.id });
                          }
                        }}
                      >
                        <Trash2 className="h-3.5 w-3.5" /> Remove
                      </Button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </DashboardLayout>
  );
}
