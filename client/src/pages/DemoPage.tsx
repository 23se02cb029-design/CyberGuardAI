import { useState } from "react";
import DashboardLayout from "@/components/DashboardLayout";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { useTheme } from "@/contexts/ThemeContext";
import { getRiskProfile } from "@/lib/risk";
import { trpc } from "@/lib/trpc";
import {
  ShieldAlert,
  ShieldCheck,
  Loader2,
  FileText,
  AlertTriangle,
  Info,
  Zap,
  Terminal,
  Radar,
  ChevronDown,
  Cpu,
} from "lucide-react";

interface Storytelling {
  why_dangerous: string;
  if_ignored: string;
  mitigation: string;
}

interface IncidentReport {
  report_metadata: { report_id: string; timestamp: string; status: string };
  executive_summary: { overview: string; impact_level: string };
  technical_details: { detected_threat: string; ai_reasoning: string };
  remediation_plan: { immediate_action: string; long_term_strategy: string };
}

interface AnalysisResult {
  threat_type: string;
  risk_score: number;
  reasoning: string;
  recommendation: string;
  storytelling: Storytelling;
  report: IncidentReport;
  source?: "gemini" | "heuristics";
}

export default function DemoPage() {
  const { theme } = useTheme();
  const isDark = theme === "dark";

  const [logData, setLogData] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");
  const [reportOpen, setReportOpen] = useState(false);
  const trpcUtils = trpc.useUtils();

  const handleAnalyze = async () => {
    if (!logData.trim()) return;
    setIsLoading(true);
    setError("");
    setResult(null);
    setReportOpen(false);

    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ logData }),
      });
      if (!response.ok) {
        const failure = await response.json().catch(() => null);
        throw new Error(failure?.error || `Analysis failed (${response.status})`);
      }
      const data = await response.json();
      setResult(data);
      void trpcUtils.threats.list.invalidate();
      void trpcUtils.dashboard.metrics.invalidate();
    } catch (e) {
      setError(`ANALYSIS_FAILED — ${e instanceof Error ? e.message : "check log formatting and retry"}`);
      console.error("Error analyzing logs:", e);
    } finally {
      setIsLoading(false);
    }
  };

  const setSampleLog = () => {
    setLogData(
      "Jan 24 10:15:03 auth-server sshd[1234]: Failed password for admin from 192.168.1.105 port 54321 ssh2\nJan 24 10:15:05 auth-server sshd[1234]: Failed password for admin from 192.168.1.105 port 54322 ssh2\nJan 24 10:15:07 auth-server sshd[1234]: Failed password for admin from 192.168.1.105 port 54323 ssh2"
    );
  };

  const riskProfile = result ? getRiskProfile(result.risk_score) : null;
  const risk = riskProfile
    ? { ...riskProfile, glow: isDark ? riskProfile.glowDark : riskProfile.glowLight }
    : null;

  return (
    <DashboardLayout>
      <div className="-m-4">
        <div className="blueprint-grid min-h-[calc(100vh-2rem)] bg-zinc-50 p-6 text-zinc-900 dark:bg-zinc-950 dark:text-zinc-100">
          {/* Header */}
          <div className="mb-6 flex flex-wrap items-center justify-between gap-4 border-b border-zinc-200 pb-6 dark:border-cyan-500/20">
            <div className="space-y-1">
              <div className="flex items-center gap-2 text-cyan-600 dark:text-cyan-400">
                <Terminal className="h-5 w-5" />
                <span className="tech-label text-cyan-600 dark:text-cyan-400">CyberGuard AI // Ops Console</span>
              </div>
              <h1 className="text-3xl font-black tracking-tighter text-zinc-900 sm:text-4xl dark:text-white">
                Threat Analysis Terminal
              </h1>
            </div>
            <div className="flex items-center gap-2">
              <Badge className="gap-1.5 border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                SYSTEM ONLINE
              </Badge>
              <Badge className="gap-1.5 border-cyan-500/40 bg-cyan-500/10 text-cyan-700 dark:text-cyan-400">
                <Zap className="h-3 w-3" />
                {result?.source === "heuristics" ? "HEURISTICS ENGINE ACTIVE" : "GEMINI REASONING ACTIVE"}
              </Badge>
            </div>
          </div>

          {/* 3-column control grid */}
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
            {/* LEFT: Log input tools */}
            <div className="lg:col-span-3">
              <div className="rounded-xl border border-zinc-200 bg-white p-5 backdrop-blur-sm dark:border-cyan-500/30 dark:bg-zinc-900/60">
                <div className="mb-4 flex items-center gap-2">
                  <Radar className="h-4 w-4 text-cyan-600 dark:text-cyan-400" />
                  <span className="tech-label text-zinc-500 dark:text-zinc-400">Log Input // Stream</span>
                </div>
                <Textarea
                  placeholder="Paste raw security logs here..."
                  className="min-h-[220px] resize-none !border-zinc-300 !bg-zinc-50 font-mono text-xs text-zinc-800 placeholder:text-zinc-400 focus-visible:!border-cyan-600/60 focus-visible:!ring-cyan-600/20 dark:!border-zinc-700 dark:!bg-black/40 dark:text-emerald-300 dark:placeholder:text-zinc-600 dark:focus-visible:!border-cyan-500/60 dark:focus-visible:!ring-cyan-500/20"
                  value={logData}
                  onChange={(e) => setLogData(e.target.value)}
                />
                <div className="mt-4 space-y-2">
                  <Button
                    onClick={handleAnalyze}
                    disabled={isLoading || !logData.trim()}
                    className="w-full !border-2 !border-cyan-600/50 !bg-cyan-50 !text-cyan-700 font-semibold tracking-wide shadow-none transition-all duration-300 hover:!bg-cyan-100 dark:!border-cyan-400/70 dark:!bg-cyan-500/25 dark:!text-cyan-100 dark:shadow-[0_0_14px_rgba(34,211,238,0.35)] dark:hover:!border-cyan-300 dark:hover:!bg-cyan-500/40 dark:hover:shadow-[0_0_28px_rgba(34,211,238,0.6)] disabled:opacity-40 disabled:shadow-none"
                    variant="outline"
                  >
                    {isLoading ? (
                      <>
                        <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Analyzing...
                      </>
                    ) : (
                      "Run AI Analysis"
                    )}
                  </Button>
                  <Button
                    variant="ghost"
                    onClick={setSampleLog}
                    className="w-full !text-zinc-600 hover:!bg-zinc-100 hover:!text-zinc-900 dark:!text-zinc-400 dark:hover:!bg-zinc-800 dark:hover:!text-zinc-100"
                  >
                    Load Attack Sample
                  </Button>
                </div>
                <div className="mt-6 space-y-1.5 border-t border-zinc-200 pt-4 text-xs text-zinc-500 dark:border-zinc-800">
                  <p className="tech-label text-zinc-500 dark:text-zinc-600">Accepted Formats</p>
                  <p>• Syslog / plain text</p>
                  <p>• CSV with headers</p>
                  <p>• JSON arrays</p>
                </div>
              </div>
            </div>

            {/* CENTER: Gemini reasoning console */}
            <div className="lg:col-span-6">
              <div className="overflow-hidden rounded-xl border border-zinc-200 bg-white backdrop-blur-sm dark:border-cyan-500/30 dark:bg-black/50 dark:shadow-[0_0_24px_rgba(34,211,238,0.08)]">
                {/* Terminal title bar */}
                <div className="flex items-center justify-between border-b border-zinc-200 bg-zinc-50 px-4 py-2.5 dark:border-cyan-500/20 dark:bg-zinc-900/80">
                  <div className="flex items-center gap-3">
                    <div className="flex gap-1.5">
                      <span className="h-2.5 w-2.5 rounded-full bg-red-500/70" />
                      <span className="h-2.5 w-2.5 rounded-full bg-amber-500/70" />
                      <span className="h-2.5 w-2.5 rounded-full bg-emerald-500/70" />
                    </div>
                    <span className="font-mono text-xs text-zinc-500">gemini_reasoning_engine.sh</span>
                  </div>
                  {isLoading && (
                    <Badge className="gap-1.5 border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-400">
                      <span className="h-1.5 w-1.5 rounded-full bg-amber-400 animate-pulse" />
                      ANALYZING
                    </Badge>
                  )}
                  {result && !isLoading && (
                    <Badge className={`gap-1.5 ${risk!.badge}`}>
                      <span className={`h-1.5 w-1.5 rounded-full bg-current animate-pulse`} />
                      {risk!.tone === "red" ? "THREAT_DETECTED" : "SCAN_COMPLETE"}
                    </Badge>
                  )}
                </div>

                {/* Terminal body */}
                <div className="relative min-h-[420px] p-5 font-mono text-sm">
                  {isLoading && (
                    <div className="absolute inset-x-0 top-0 h-0.5 overflow-hidden bg-cyan-600/10 dark:bg-cyan-500/10">
                      <div className="h-full w-1/4 bg-cyan-600/70 animate-hud-scan dark:bg-cyan-400/80" />
                    </div>
                  )}

                  {!result && !isLoading && !error && (
                    <div className="flex h-[380px] flex-col items-center justify-center gap-3 text-zinc-400 dark:text-zinc-600">
                      <Cpu className="h-10 w-10 opacity-40" />
                      <p className="tech-label">Awaiting Log Stream</p>
                      <p className="text-zinc-400 dark:text-zinc-700">
                        <span className="text-cyan-600 dark:text-cyan-500">$</span> standby
                        {isDark && <span className="animate-hud-blink">▊</span>}
                      </p>
                    </div>
                  )}

                  {isLoading && (
                    <div className="flex h-[380px] flex-col items-center justify-center gap-3 text-amber-600 dark:text-amber-400/80">
                      <Loader2 className="h-8 w-8 animate-spin" />
                      <p className="tech-label text-amber-600 dark:text-amber-400/80">Analyzing Pattern Signatures...</p>
                    </div>
                  )}

                  {error && !isLoading && (
                    <div className="flex h-[380px] flex-col items-center justify-center gap-3 text-red-600 dark:text-red-400">
                      <AlertTriangle className="h-8 w-8" />
                      <p className="font-mono text-sm">[ERROR] {error}</p>
                    </div>
                  )}

                  {result && !isLoading && (
                    <div className="animate-in fade-in slide-in-from-bottom-2 duration-500 space-y-4">
                      <p className="text-zinc-500">
                        <span className="text-cyan-600 dark:text-cyan-500">$</span> ./analyze --input=log_stream.txt
                      </p>

                      <div className="space-y-1">
                        <p>
                          <span className="text-zinc-500 dark:text-zinc-600">{">"} THREAT_TYPE:</span>{" "}
                          <span className="font-semibold text-zinc-900 dark:text-white">{result.threat_type}</span>
                        </p>
                        <p>
                          <span className="text-zinc-500 dark:text-zinc-600">{">"} RISK_SCORE:</span>{" "}
                          <span className={`text-lg font-black ${risk!.glow}`}>
                            {result.risk_score}
                          </span>
                          <span className="text-zinc-500 dark:text-zinc-600">/100</span>
                        </p>
                        <p>
                          <span className="text-zinc-500 dark:text-zinc-600">{">"} STATUS:</span>{" "}
                          <span className={`font-semibold ${risk!.glow}`}>{risk!.level}</span>
                        </p>
                      </div>

                      <div
                        className="animate-in fade-in slide-in-from-left-2 duration-500 space-y-1 border-l-2 border-cyan-500/30 pl-3"
                        style={{ animationDelay: "120ms" }}
                      >
                        <p className="text-zinc-500 dark:text-zinc-600">{">"} REASONING:</p>
                        <p className="leading-relaxed text-zinc-700 dark:text-zinc-300">"{result.reasoning}"</p>
                      </div>

                      <div
                        className="animate-in fade-in slide-in-from-left-2 duration-500 space-y-1 border-l-2 border-amber-500/30 pl-3"
                        style={{ animationDelay: "260ms" }}
                      >
                        <p className="text-amber-600 dark:text-amber-500/80">[WARN] WHY_DANGEROUS:</p>
                        <p className="leading-relaxed text-zinc-600 dark:text-zinc-400">{result.storytelling.why_dangerous}</p>
                      </div>

                      <div
                        className="animate-in fade-in slide-in-from-left-2 duration-500 space-y-1 border-l-2 border-zinc-400/40 pl-3 dark:border-zinc-600/40"
                        style={{ animationDelay: "400ms" }}
                      >
                        <p className="text-zinc-500">[INFO] IF_IGNORED:</p>
                        <p className="leading-relaxed text-zinc-600 dark:text-zinc-400">{result.storytelling.if_ignored}</p>
                      </div>

                      <div
                        className="animate-in fade-in slide-in-from-left-2 duration-500 space-y-1 border-l-2 border-emerald-500/30 pl-3"
                        style={{ animationDelay: "540ms" }}
                      >
                        <p className="text-emerald-600 dark:text-emerald-500/80">[ACTION] RECOMMENDATION:</p>
                        <p className="leading-relaxed font-semibold text-emerald-700 dark:text-emerald-300">
                          {result.recommendation}
                        </p>
                      </div>

                      <p className="pt-2 text-zinc-500 dark:text-zinc-600">
                        <span className="text-cyan-600 dark:text-cyan-500">$</span>{" "}
                        {isDark && <span className="animate-hud-blink">▊</span>}
                      </p>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* RIGHT: Live incident-report metrics */}
            <div className="space-y-4 lg:col-span-3">
              <div
                className={`rounded-xl border p-4 transition-all duration-500 ${
                  risk ? risk.border : "border-zinc-200 dark:border-zinc-800"
                } ${risk ? risk.bg : "bg-white dark:bg-zinc-900/60"}`}
              >
                <p className="tech-label mb-2 text-zinc-500">Risk Score</p>
                <div
                  className={`text-4xl font-black transition-all duration-500 ${
                    risk ? risk.glow : "text-zinc-300 dark:text-zinc-700"
                  }`}
                >
                  {result ? result.risk_score : "--"}
                  <span className="text-base text-zinc-500 dark:text-zinc-600">/100</span>
                </div>
                <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-zinc-200 dark:bg-zinc-800">
                  <div
                    className={`h-full rounded-full transition-all duration-700 ease-out ${
                      risk ? risk.bar : "bg-zinc-300 dark:bg-zinc-700"
                    }`}
                    style={{ width: `${result ? result.risk_score : 0}%` }}
                  />
                </div>
              </div>

              <div className="rounded-xl border border-zinc-200 bg-white p-4 dark:border-zinc-800 dark:bg-zinc-900/60">
                <p className="tech-label mb-2 text-zinc-500">Threat Classification</p>
                <div className="flex items-center gap-2">
                  {result ? (
                    risk!.tone === "red" ? (
                      <ShieldAlert className={`h-5 w-5 ${risk!.glow}`} />
                    ) : (
                      <ShieldCheck className={`h-5 w-5 ${risk!.glow}`} />
                    )
                  ) : (
                    <ShieldCheck className="h-5 w-5 text-zinc-300 dark:text-zinc-700" />
                  )}
                  <span className="text-sm font-semibold text-zinc-800 dark:text-zinc-200">
                    {result ? result.threat_type : "No active detections"}
                  </span>
                </div>
              </div>

              <div className="rounded-xl border border-zinc-200 bg-white p-4 dark:border-zinc-800 dark:bg-zinc-900/60">
                <p className="tech-label mb-2 text-zinc-500">Cluster Status</p>
                {result ? (
                  <Badge className={`gap-1.5 ${risk!.badge}`}>
                    <span className="h-1.5 w-1.5 rounded-full bg-current animate-pulse" />
                    {result.report.report_metadata.status}
                  </Badge>
                ) : (
                  <Badge className="border-zinc-300 bg-zinc-100 text-zinc-500 dark:border-zinc-700 dark:bg-zinc-800">
                    STANDBY
                  </Badge>
                )}
              </div>

              <Collapsible open={reportOpen} onOpenChange={setReportOpen}>
                <div className="overflow-hidden rounded-xl border border-zinc-200 bg-white dark:border-cyan-500/30 dark:bg-zinc-900/60">
                  <CollapsibleTrigger asChild>
                    <button
                      disabled={!result}
                      className="flex w-full items-center justify-between px-4 py-3 text-left text-sm font-semibold text-zinc-800 transition-colors hover:bg-zinc-100 disabled:cursor-not-allowed disabled:opacity-40 dark:text-zinc-200 dark:hover:bg-zinc-800/60"
                    >
                      <span className="flex items-center gap-2">
                        <FileText className="h-4 w-4 text-cyan-600 dark:text-cyan-400" />
                        Incident Report
                      </span>
                      <ChevronDown
                        className={`h-4 w-4 text-zinc-500 transition-transform duration-300 ${
                          reportOpen ? "rotate-180" : ""
                        }`}
                      />
                    </button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="overflow-hidden data-[state=closed]:animate-out data-[state=closed]:fade-out data-[state=closed]:slide-out-to-top-1 data-[state=open]:animate-in data-[state=open]:fade-in data-[state=open]:slide-in-from-top-1">
                    {result && (
                      <div className="space-y-4 border-t border-zinc-200 bg-zinc-50 p-4 font-mono text-xs leading-relaxed text-zinc-600 dark:border-zinc-800 dark:bg-black/40 dark:text-zinc-400">
                        <div className="flex items-center justify-between text-zinc-500">
                          <span>{result.report.report_metadata.report_id}</span>
                          <Badge className={`${risk!.badge} text-[10px]`}>
                            {result.report.report_metadata.status}
                          </Badge>
                        </div>
                        <section>
                          <h4 className="mb-1 text-cyan-700 dark:text-cyan-400">EXECUTIVE_SUMMARY</h4>
                          <p>{result.report.executive_summary.overview}</p>
                          <p className="mt-1 text-zinc-500">
                            IMPACT: {result.report.executive_summary.impact_level}
                          </p>
                        </section>
                        <section>
                          <h4 className="mb-1 text-cyan-700 dark:text-cyan-400">TECHNICAL_ANALYSIS</h4>
                          <p>DETECTED: {result.report.technical_details.detected_threat}</p>
                          <p className="mt-1">{result.report.technical_details.ai_reasoning}</p>
                        </section>
                        <section>
                          <h4 className="mb-1 text-cyan-700 dark:text-cyan-400">REMEDIATION_PLAN</h4>
                          <p>IMMEDIATE: {result.report.remediation_plan.immediate_action}</p>
                          <p className="mt-1">
                            STRATEGY: {result.report.remediation_plan.long_term_strategy}
                          </p>
                        </section>
                        <p className="border-t border-zinc-200 pt-2 text-[10px] text-zinc-500 dark:border-zinc-800 dark:text-zinc-600">
                          GENERATED_BY: CYBERGUARD_AI_CORE // {result.report.report_metadata.timestamp}
                        </p>
                      </div>
                    )}
                  </CollapsibleContent>
                </div>
              </Collapsible>

              <div className="flex items-start gap-2 rounded-xl border border-zinc-200 bg-zinc-50 p-3 text-xs text-zinc-500 dark:border-zinc-800 dark:bg-zinc-900/40">
                <Info className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                <p>
                  {!result
                    ? "Analysis runs on live Gemini inference; falls back to the local heuristics engine if no API key is configured."
                    : result.source === "heuristics"
                      ? "GEMINI_API_KEY not configured (or the live call failed) — showing results from the local regex/heuristics detection engine."
                      : "Live Gemini reasoning — results generated in real time."}
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}
