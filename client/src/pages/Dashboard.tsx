import { analyzeLogs } from "@/lib/api";
import { Textarea } from "@/components/ui/textarea";
import { useAuth } from "@/_core/hooks/useAuth";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import DashboardLayout from "@/components/DashboardLayout";
import { useTheme } from "@/contexts/ThemeContext";
import { getRiskProfile } from "@/lib/risk";
import { trpc } from "@/lib/trpc";
import { AlertTriangle, BarChart3, FileText, Loader2, Network, Shield, Terminal, TrendingUp, Upload, Zap } from "lucide-react";
import { Area, AreaChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useEffect, useRef, useState } from "react";
import { useLocation } from "wouter";

export default function Dashboard() {
  const { user } = useAuth();
  const { theme } = useTheme();
  const isDark = theme === "dark";
  const [, navigate] = useLocation();
  const [metrics, setMetrics] = useState<any>(null);
  const isAdmin = user?.role === "admin";
  const metricsQuery = trpc.dashboard.metrics.useQuery();
  const threatsQuery = trpc.threats.list.useQuery({ limit: 5, offset: 0 }, { enabled: Boolean(isAdmin) });
  const trpcUtils = trpc.useUtils();
  const [logData, setLogData] = useState("");
  const [analysis, setAnalysis] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const logTextareaRef = useRef<HTMLTextAreaElement>(null);

  async function handleAnalyzeThreats() {
    if (!logData.trim()) {
      setError("Please paste log data");
      return;
    }

    try {
      setLoading(true);
      setError("");
      const result = await analyzeLogs(logData);
      setAnalysis(result);
      void trpcUtils.threats.list.invalidate();
      void trpcUtils.dashboard.metrics.invalidate();
    } catch (e) {
      setError("Failed to analyze logs");
    } finally {
      setLoading(false);
    }
  }

  async function handleLiveNetworkScan() {
    try {
      setLoading(true);
      setError("");

      const response = await fetch("/api/live-network", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
      });

      const result = await response.json();

      if (!response.ok || result.error) {
        throw new Error(result.error || "Live network analysis failed");
      }

      const mappedResult = {
        threat_type: result.vulnerabilities?.[0] || "Suspicious Activity",
        risk_score: result.riskScore,
        reasoning: result.reasoning,
        recommendation: result.remediationSteps?.[0] || "Continue routine monitoring.",
      };

      setAnalysis(mappedResult);
      void trpcUtils.threats.list.invalidate();
      void trpcUtils.dashboard.metrics.invalidate();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to run live network scan");
    } finally {
      setLoading(false);
    }
  }

  function focusLogTextarea() {
    logTextareaRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
    logTextareaRef.current?.focus();
  }

  useEffect(() => {
    if (metricsQuery.data) {
      setMetrics(metricsQuery.data);
    }
  }, [metricsQuery.data]);

  const threatCount = metrics?.threatCount || 0;
  const avgRiskScore = metrics?.avgRiskScore || 0;
  const criticalThreats = metrics?.criticalThreats || 0;
  const highThreats = metrics?.highThreats || 0;
  const mediumThreats = metrics?.mediumThreats || 0;
  const eventsAnalyzed = metrics?.eventsAnalyzed || 0;
  const hasSuspiciousAlerts = criticalThreats > 0 || highThreats > 0 || mediumThreats > 0 || Boolean(analysis?.risk_score >= 30);
  const securityStatus = criticalThreats > 0 ? "CRITICAL" : highThreats > 0 ? "ALERT" : mediumThreats > 0 ? "ELEVATED" : "NORMAL";

  const avgRisk = getRiskProfile(avgRiskScore);
  const avgGlow = isDark ? avgRisk.glowDark : avgRisk.glowLight;
  const analysisRisk = analysis ? getRiskProfile(analysis.risk_score) : null;
  const analysisGlow = analysisRisk ? (isDark ? analysisRisk.glowDark : analysisRisk.glowLight) : "";
  const severityData = [
    { name: "Critical", value: criticalThreats, color: "#ef4444" },
    { name: "High", value: highThreats, color: "#f97316" },
    { name: "Medium", value: mediumThreats, color: "#f59e0b" },
    { name: "Low", value: metrics?.lowThreats || 0, color: "#22d3ee" },
  ];
  const trendData = (threatsQuery.data || []).reduce<Array<{ time: string; threats: number }>>((points, threat) => {
    const time = new Date(threat.createdAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    const existing = points.find((point) => point.time === time);
    if (existing) existing.threats += 1;
    else points.push({ time, threats: 1 });
    return points;
  }, []).slice(-12);
  const sourceCounts = Object.entries((threatsQuery.data || []).reduce<Record<string, number>>((counts, threat) => {
    const source = (threat.affectedAssets as { sourceIp?: string } | null)?.sourceIp;
    if (source) counts[source] = (counts[source] || 0) + 1;
    return counts;
  }, {})).sort(([, left], [, right]) => right - left).slice(0, 4);

  return (
    <DashboardLayout>
      <div className="-m-4">
        <div className="blueprint-grid min-h-[calc(100vh-2rem)] bg-background p-5 text-foreground sm:p-7">
          {/* Header */}
          <div className="mb-7 flex flex-wrap items-end justify-between gap-4 border-b border-cyan-400/10 pb-6">
            <div className="space-y-1">
              <div className="flex items-center gap-2 text-cyan-300">
                <Terminal className="h-5 w-5" />
                <span className="tech-label text-cyan-300">CyberGuard AI // Command Center</span>
              </div>
              <h1 className="text-3xl font-black tracking-tight text-slate-900 sm:text-4xl dark:text-white">
                Security Operations Overview
              </h1>
              <p className="mt-2 max-w-xl text-sm text-slate-600 dark:text-muted-foreground">
                Real-time threat detection, log analysis, and network monitoring.
              </p>
            </div>
            <div className="text-right"><p className="text-xs text-slate-500">{new Date().toLocaleString()}</p><Badge className="mt-2 gap-1.5 border-emerald-500/30 bg-emerald-400/10 text-emerald-300">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
              SYSTEM ONLINE
            </Badge><p className="mt-1 text-[11px] text-slate-500">All systems operational</p></div>
          </div>

          {/* KPI Cards */}
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
            <div className="soc-surface soc-surface-hover rounded-xl p-5">
              <div className="mb-2 flex items-center justify-between">
                <p className="tech-label">Average Risk Score</p>
                <TrendingUp className="h-4 w-4 text-cyan-300" />
              </div>
              <div className={`text-4xl font-black ${avgGlow}`}>
                {avgRiskScore.toFixed(1)}
                <span className="text-base text-slate-500">/100</span>
              </div>
              <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
                <div className={`h-full rounded-full transition-all duration-700 ease-out ${avgRisk.bar}`} style={{ width: `${avgRiskScore}%` }} />
              </div>
            </div>

            <div className="soc-surface soc-surface-hover rounded-xl p-5">
              <div className="mb-2 flex items-center justify-between">
                <p className="tech-label">Total Threats Detected</p>
                <BarChart3 className="h-4 w-4 text-cyan-300" />
              </div>
              <div className="text-4xl font-black text-slate-900 dark:text-glow-cyan">{threatCount}</div>
              <p className="mt-3 text-xs text-slate-500">Evidence-backed incidents</p>
            </div>

            <div className={`soc-surface rounded-xl p-5 ${criticalThreats > 0 ? "border-red-500/50" : ""}`}>
              <div className="mb-2 flex items-center justify-between">
                <p className="tech-label">Critical Threats</p>
                <AlertTriangle className={`h-4 w-4 ${criticalThreats > 0 ? "text-red-500" : "text-zinc-400"}`} />
              </div>
              <div className={`text-4xl font-black ${criticalThreats > 0 ? (isDark ? "text-glow-red" : "text-red-600") : "text-slate-800 dark:text-white"}`}>
                {criticalThreats}
              </div>
              <p className="mt-3 text-xs text-slate-500">Risk score ≥ 80</p>
            </div>

            <div className="soc-surface soc-surface-hover rounded-xl p-5">
              <div className="mb-2 flex items-center justify-between">
                <p className="tech-label">Security Status</p>
                <Shield className={`h-4 w-4 ${hasSuspiciousAlerts ? "text-red-500" : "text-emerald-500"}`} />
              </div>
              <div className={`text-2xl font-black ${hasSuspiciousAlerts ? (isDark ? "text-glow-red" : "text-red-600") : (isDark ? "text-glow-green" : "text-emerald-600")}`}>
                {securityStatus}
              </div>
              <p className="mt-3 text-xs text-zinc-500 dark:text-zinc-600">
                {hasSuspiciousAlerts ? "Evidence-backed activity detected" : "No suspicious activity"}
              </p>
            </div>
          </div>

          <div className="mt-4 grid grid-cols-2 gap-3 text-sm md:grid-cols-5">
            {[
              ["Events Analyzed", eventsAnalyzed],
              ["Unique Incidents", metrics?.uniqueIncidents || threatCount],
              ["High", highThreats],
              ["Medium", mediumThreats],
              ["Low", metrics?.lowThreats || 0],
            ].map(([label, value]) => (
              <div key={label} className="border-l border-cyan-400/30 pl-3">
                <p className="tech-label">{label}</p>
                <p className="text-xl font-bold text-slate-800 dark:text-slate-100">{value}</p>
              </div>
            ))}
          </div>

          <div className="mt-7 grid grid-cols-1 gap-4 xl:grid-cols-[1.55fr_0.85fr]">
            <section className="soc-surface rounded-xl p-5">
              <div className="mb-5 flex items-start justify-between"><div><p className="tech-label text-cyan-700 dark:text-cyan-300">Threat Trends</p><h2 className="mt-1 text-lg font-semibold text-slate-900 dark:text-white">Detections over the last 24 hours</h2></div><span className="text-xs text-slate-500">Live query data</span></div>
              {trendData.length ? <ResponsiveContainer width="100%" height={220}><AreaChart data={trendData}><defs><linearGradient id="threatFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#22d3ee" stopOpacity={0.32} /><stop offset="100%" stopColor="#22d3ee" stopOpacity={0} /></linearGradient></defs><CartesianGrid stroke="rgba(120,160,190,.12)" vertical={false} /><XAxis dataKey="time" tick={{ fill: "#7890aa", fontSize: 11 }} axisLine={false} tickLine={false} /><YAxis allowDecimals={false} tick={{ fill: "#7890aa", fontSize: 11 }} axisLine={false} tickLine={false} /><Tooltip contentStyle={{ background: "#0a1423", border: "1px solid rgba(34,211,238,.3)", borderRadius: 8, color: "#dbeafe" }} /><Area type="monotone" dataKey="threats" stroke="#22d3ee" strokeWidth={2} fill="url(#threatFill)" /></AreaChart></ResponsiveContainer> : <div className="flex h-[220px] items-center justify-center rounded-lg border border-dashed border-slate-700 text-sm text-slate-500">No threat trend data available</div>}
            </section>
            <section className="soc-surface rounded-xl p-5"><div className="mb-2"><p className="tech-label text-violet-700 dark:text-violet-300">Threat Distribution</p><h2 className="mt-1 text-lg font-semibold text-slate-900 dark:text-white">By severity</h2></div>{threatCount ? <div className="relative h-[220px]"><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={severityData} dataKey="value" nameKey="name" innerRadius={62} outerRadius={88} paddingAngle={3}>{severityData.map((entry) => <Cell key={entry.name} fill={entry.color} />)}</Pie><Tooltip contentStyle={{ background: "#0a1423", border: "1px solid rgba(167,139,250,.3)", borderRadius: 8 }} /></PieChart></ResponsiveContainer><div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center"><span className="text-3xl font-bold text-slate-800 dark:text-white">{threatCount}</span><span className="text-[10px] uppercase tracking-widest text-slate-500">total</span></div></div> : <div className="flex h-[220px] items-center justify-center text-sm text-slate-500">No distribution data available</div>}<div className="grid grid-cols-2 gap-2 text-xs">{severityData.map((entry) => <div key={entry.name} className="flex items-center justify-between text-slate-600 dark:text-slate-400"><span><i className="mr-2 inline-block h-2 w-2 rounded-full" style={{ background: entry.color }} />{entry.name}</span><strong className="text-slate-700 dark:text-slate-200">{entry.value}</strong></div>)}</div></section>
          </div>

          <section className="soc-surface mt-4 rounded-xl p-5"><div className="mb-4 flex items-center justify-between"><div><p className="tech-label text-cyan-700 dark:text-cyan-300">Top Source IPs</p><h2 className="mt-1 text-lg font-semibold text-slate-900 dark:text-white">Most active evidence sources</h2></div><span className="text-xs text-slate-500">No fabricated values</span></div>{sourceCounts.length ? <div className="space-y-3">{sourceCounts.map(([source, count]) => <div key={source} className="grid grid-cols-[9rem_1fr_2rem] items-center gap-3 text-sm"><span className="font-mono text-slate-700 dark:text-slate-300">{source}</span><div className="h-2 rounded-full bg-slate-200 dark:bg-slate-800"><div className="h-full rounded-full bg-cyan-400" style={{ width: `${Math.max(8, (count / sourceCounts[0][1]) * 100)}%` }} /></div><span className="text-right text-slate-600 dark:text-slate-400">{count}</span></div>)}</div> : <p className="py-5 text-sm text-slate-500">No source IP data available</p>}</section>

          {/* Quick Actions */}
          <div className="mt-8 space-y-3">
            <p className="tech-label text-zinc-500 dark:text-zinc-400">Quick Actions</p>
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
              <Button
                className="h-20 !border-2 !border-cyan-600/50 !bg-cyan-50 !text-cyan-700 font-semibold tracking-wide shadow-none transition-all duration-300 hover:!bg-cyan-100 dark:!border-cyan-400/70 dark:!bg-cyan-500/25 dark:!text-cyan-100 dark:shadow-[0_0_14px_rgba(34,211,238,0.35)] dark:hover:!border-cyan-300 dark:hover:!bg-cyan-500/40 dark:hover:shadow-[0_0_28px_rgba(34,211,238,0.6)]"
                variant="outline"
                onClick={() => navigate("/logs/upload")}
              >
                <Upload className="mr-2 inline-block h-4 w-4" /> Upload Logs
              </Button>
              <Button
                className="h-20 !border-2 !border-cyan-600/50 !bg-cyan-50 !text-cyan-700 font-semibold tracking-wide shadow-none transition-all duration-300 hover:!bg-cyan-100 dark:!border-cyan-400/70 dark:!bg-cyan-500/25 dark:!text-cyan-100 dark:shadow-[0_0_14px_rgba(34,211,238,0.35)] dark:hover:!border-cyan-300 dark:hover:!bg-cyan-500/40 dark:hover:shadow-[0_0_28px_rgba(34,211,238,0.6)]"
                variant="outline"
                onClick={focusLogTextarea}
              >
                <Zap className="mr-2 inline-block h-4 w-4" /> Analyze Threats
              </Button>
              <Button
                className="h-20 !border-2 !border-cyan-600/50 !bg-cyan-50 !text-cyan-700 font-semibold tracking-wide shadow-none transition-all duration-300 hover:!bg-cyan-100 dark:!border-cyan-400/70 dark:!bg-cyan-500/25 dark:!text-cyan-100 dark:shadow-[0_0_14px_rgba(34,211,238,0.35)] dark:hover:!border-cyan-300 dark:hover:!bg-cyan-500/40 dark:hover:shadow-[0_0_28px_rgba(34,211,238,0.6)]"
                variant="outline"
                onClick={handleLiveNetworkScan}
                disabled={loading}
              >
                <Network className="mr-2 inline-block h-4 w-4" /> {loading ? "Scanning..." : "Live Network Scan"}
              </Button>
              <Button
                className="h-20 !border-2 !border-cyan-600/50 !bg-cyan-50 !text-cyan-700 font-semibold tracking-wide shadow-none transition-all duration-300 hover:!bg-cyan-100 dark:!border-cyan-400/70 dark:!bg-cyan-500/25 dark:!text-cyan-100 dark:shadow-[0_0_14px_rgba(34,211,238,0.35)] dark:hover:!border-cyan-300 dark:hover:!bg-cyan-500/40 dark:hover:shadow-[0_0_28px_rgba(34,211,238,0.6)]"
                variant="outline"
                onClick={() => navigate("/threats")}
              >
                <FileText className="mr-2 inline-block h-4 w-4" /> Generate Report
              </Button>
            </div>
          </div>

          {/* Threat Analysis Terminal */}
          <div className="mt-8 overflow-hidden rounded-xl border border-zinc-200 bg-white backdrop-blur-sm dark:border-cyan-500/30 dark:bg-black/50 dark:shadow-[0_0_24px_rgba(34,211,238,0.08)]">
            <div className="flex items-center justify-between border-b border-zinc-200 bg-zinc-50 px-4 py-2.5 dark:border-cyan-500/20 dark:bg-zinc-900/80">
              <div className="flex items-center gap-3">
                <div className="flex gap-1.5">
                  <span className="h-2.5 w-2.5 rounded-full bg-red-500/70" />
                  <span className="h-2.5 w-2.5 rounded-full bg-amber-500/70" />
                  <span className="h-2.5 w-2.5 rounded-full bg-emerald-500/70" />
                </div>
                <span className="font-mono text-xs text-zinc-500">threat_analysis.sh</span>
              </div>
              {loading && (
                <Badge className="gap-1.5 border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-400">
                  <span className="h-1.5 w-1.5 rounded-full bg-amber-400 animate-pulse" />
                  ANALYZING
                </Badge>
              )}
            </div>
            <div className="space-y-4 p-5">
              <Textarea
                ref={logTextareaRef}
                placeholder="Paste raw security logs here..."
                className="min-h-[120px] resize-none !border-zinc-300 !bg-zinc-50 font-mono text-xs text-zinc-800 placeholder:text-zinc-400 focus-visible:!border-cyan-600/60 focus-visible:!ring-cyan-600/20 dark:!border-zinc-700 dark:!bg-black/40 dark:text-emerald-300 dark:placeholder:text-zinc-600 dark:focus-visible:!border-cyan-500/60 dark:focus-visible:!ring-cyan-500/20"
                value={logData}
                onChange={(e) => setLogData(e.target.value)}
              />

              <Button
                onClick={handleAnalyzeThreats}
                disabled={loading}
                className="!border-2 !border-cyan-600/50 !bg-cyan-50 !text-cyan-700 font-semibold tracking-wide shadow-none transition-all duration-300 hover:!bg-cyan-100 dark:!border-cyan-400/70 dark:!bg-cyan-500/25 dark:!text-cyan-100 dark:hover:!border-cyan-300 dark:hover:!bg-cyan-500/40 disabled:opacity-40"
                variant="outline"
              >
                {loading ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Analyzing...
                  </>
                ) : (
                  "Run AI Analysis"
                )}
              </Button>

              {error && (
                <p className="flex items-center gap-2 font-mono text-sm text-red-600 dark:text-red-400">
                  <AlertTriangle className="h-4 w-4" /> [ERROR] {error}
                </p>
              )}

              {analysis && (
                <div className="animate-in fade-in slide-in-from-bottom-2 duration-500 space-y-3 border-t border-zinc-200 pt-4 font-mono text-sm dark:border-zinc-800">
                  <p>
                    <span className="text-zinc-500 dark:text-zinc-600">{">"} THREAT_TYPE:</span>{" "}
                    <span className="font-semibold text-zinc-900 dark:text-white">{analysis.threat_type}</span>
                  </p>
                  <p>
                    <span className="text-zinc-500 dark:text-zinc-600">{">"} RISK_SCORE:</span>{" "}
                    <span className={`text-lg font-black ${analysisGlow}`}>{analysis.risk_score}</span>
                    <span className="text-zinc-500 dark:text-zinc-600">/100</span>
                  </p>
                  <div className="space-y-1 border-l-2 border-cyan-500/30 pl-3">
                    <p className="text-zinc-500 dark:text-zinc-600">{">"} REASONING:</p>
                    <p className="leading-relaxed text-zinc-700 dark:text-zinc-300">{analysis.reasoning}</p>
                  </div>
                  <div className="space-y-1 border-l-2 border-emerald-500/30 pl-3">
                    <p className="text-emerald-600 dark:text-emerald-500/80">[ACTION] IMMEDIATE:</p>
                    <p className="leading-relaxed font-semibold text-emerald-700 dark:text-emerald-300">
                      {analysis.recommendation}
                    </p>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Recent Activity */}
          <div className="mt-8 space-y-3">
            <p className="tech-label text-zinc-500 dark:text-zinc-400">Recent Activity</p>
            <div className="rounded-xl border border-zinc-200 bg-white p-8 text-center dark:border-cyan-500/30 dark:bg-zinc-900/60">
              {!isAdmin ? (
                <div className="py-2">
                  <p className="tech-label text-zinc-500 dark:text-zinc-400">Restricted Feed</p>
                  <p className="mt-1 text-xs text-muted-foreground">Admin permissions required to view the global threat feed.</p>
                </div>
              ) : threatsQuery.isLoading ? (
                <p className="tech-label text-zinc-500 dark:text-zinc-600">Loading recent threats...</p>
              ) : threatsQuery.isError ? (
                <p className="text-sm text-red-600 dark:text-red-400">Unable to load recent threats</p>
              ) : threatsQuery.data?.length ? (
                <div className="space-y-2 text-left">
                  {threatsQuery.data.map((threat) => (
                    <button
                      key={threat.id}
                      type="button"
                      className="flex w-full items-center justify-between gap-4 rounded-lg border border-zinc-200 p-3 text-left transition-colors hover:border-cyan-500/50 dark:border-zinc-800"
                      onClick={() => navigate(`/threats/${threat.id}`)}
                    >
                      <span className="min-w-0 truncate font-semibold capitalize text-zinc-800 dark:text-zinc-200">
                        {threat.threatType?.replace(/_/g, " ") || "Unknown threat"}
                      </span>
                      <span className="shrink-0 font-mono text-sm font-bold text-orange-600">
                        {Number(threat.riskScore || 0).toFixed(0)}/100
                      </span>
                    </button>
                  ))}
                </div>
              ) : (
                <>
                  <Zap className="mx-auto mb-3 h-8 w-8 text-zinc-300 dark:text-zinc-700" />
                  <p className="tech-label text-zinc-500 dark:text-zinc-600">No recent threats detected</p>
                </>
              )}
            </div>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}
