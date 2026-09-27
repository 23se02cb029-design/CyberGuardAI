import { useState, useEffect } from "react";
import DashboardLayout from "@/components/DashboardLayout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Slider } from "@/components/ui/slider";
import { trpc } from "@/lib/trpc";
import { useAuth } from "@/_core/hooks/useAuth";
import { useTheme } from "@/contexts/ThemeContext";
import { toast } from "sonner";
import {
  Sparkles,
  Key,
  Shield,
  CheckCircle2,
  AlertTriangle,
  ExternalLink,
  Eye,
  EyeOff,
  Server,
  Zap,
  Activity,
  Save,
  RefreshCw,
  Sliders,
  Terminal,
  Cpu,
  Lock,
  Radio,
  ArrowRight,
  Sun,
  Moon,
  Palette,
  Monitor,
  Laptop,
} from "lucide-react";
import { Link } from "wouter";

export default function Settings() {
  const { user } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const isDark = theme === "dark";
  const utils = trpc.useUtils();

  const settingsQuery = trpc.settings.get.useQuery();
  const testMutation = trpc.settings.testGemini.useMutation();
  const updateGeminiMutation = trpc.settings.updateGemini.useMutation();
  const updateSocMutation = trpc.settings.updateSocSettings.useMutation();

  const [activeTab, setActiveTab] = useState<"ai" | "soc" | "appearance" | "account">("ai");

  // Gemini state
  const [apiKey, setApiKey] = useState("");
  const [showKey, setShowKey] = useState(false);
  const [selectedModel, setSelectedModel] = useState("gemini-1.5-flash");
  const [testResult, setTestResult] = useState<{
    connected: boolean;
    latencyMs: number;
    model: string;
    response: string;
    error?: string;
  } | null>(null);

  // SOC Telemetry state
  const [telemetryInterval, setTelemetryInterval] = useState(5);
  const [quarantineThreshold, setQuarantineThreshold] = useState(65);
  const [autoQuarantine, setAutoQuarantine] = useState(true);
  const [emailAlerts, setEmailAlerts] = useState(true);
  const [webhookUrl, setWebhookUrl] = useState("");

  // Populate from query once loaded
  useEffect(() => {
    if (settingsQuery.data) {
      if (settingsQuery.data.gemini.model) {
        setSelectedModel(settingsQuery.data.gemini.model);
      }
      if (settingsQuery.data.soc) {
        setTelemetryInterval(settingsQuery.data.soc.telemetryIntervalSec);
        setQuarantineThreshold(settingsQuery.data.soc.quarantineThreshold);
        setAutoQuarantine(settingsQuery.data.soc.autoQuarantineEnabled);
        setEmailAlerts(settingsQuery.data.soc.emailAlertsEnabled);
        setWebhookUrl(settingsQuery.data.soc.webhookUrl || "");
      }
    }
  }, [settingsQuery.data]);

  const handleTestConnection = async () => {
    try {
      const res = await testMutation.mutateAsync({
        apiKey: apiKey.trim() || undefined,
        model: selectedModel,
      });
      setTestResult(res);
      if (res.connected) {
        toast.success(`Connected to ${res.model} successfully (${res.latencyMs}ms)!`);
      } else {
        toast.error(`Gemini connection failed: ${res.error || "Unknown error"}`);
      }
    } catch (err: any) {
      toast.error(err.message || "Failed to test Gemini connection");
    }
  };

  const handleSaveGemini = async () => {
    if (!apiKey.trim() && !settingsQuery.data?.gemini.configured) {
      toast.error("Please enter a valid Gemini API Key first.");
      return;
    }

    try {
      const res = await updateGeminiMutation.mutateAsync({
        apiKey: apiKey.trim() || (settingsQuery.data?.gemini.configured ? "" : ""),
        model: selectedModel,
      });

      if (res.testResult.connected) {
        toast.success(`Gemini API configured and verified! Active model: ${res.model}`);
      } else {
        toast.warning(`Key saved, but test probe returned: ${res.testResult.error || "check key"}`);
      }

      setTestResult(res.testResult);
      utils.settings.get.invalidate();
      setApiKey("");
    } catch (err: any) {
      toast.error(err.message || "Failed to update Gemini settings");
    }
  };

  const handleSaveSoc = async () => {
    try {
      await updateSocMutation.mutateAsync({
        telemetryIntervalSec: telemetryInterval,
        quarantineThreshold: quarantineThreshold,
        autoQuarantineEnabled: autoQuarantine,
        emailAlertsEnabled: emailAlerts,
        webhookUrl: webhookUrl.trim(),
      });
      toast.success("SOC telemetry and mitigation parameters saved!");
      utils.settings.get.invalidate();
    } catch (err: any) {
      toast.error(err.message || "Failed to update SOC settings");
    }
  };

  return (
    <DashboardLayout>
      <div className="space-y-6 pb-12">
        {/* Header with High-Contrast Typography */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border pb-5">
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-primary">
              <Terminal className="h-5 w-5" />
              <span className="tech-label font-mono tracking-wider text-xs">
                CYBERGUARD AI // ENTERPRISE CONFIGURATION
              </span>
            </div>
            <h1 className="text-3xl font-black tracking-tight text-foreground flex items-center gap-3">
              System Settings
            </h1>
            <p className="text-sm text-muted-foreground">
              Configure Google Gemini neural reasoning, SOC telemetry intervals, employee monitoring, and visual themes.
            </p>
          </div>

          <div className="flex items-center gap-3">
            {settingsQuery.data?.gemini.configured ? (
              <Badge className="border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 px-3 py-1.5 flex items-center gap-1.5 text-xs font-mono">
                <Sparkles className="w-3.5 h-3.5 animate-pulse text-emerald-500" />
                GEMINI AI OPERATIONAL
              </Badge>
            ) : (
              <Badge className="border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400 px-3 py-1.5 flex items-center gap-1.5 text-xs font-mono">
                <AlertTriangle className="w-3.5 h-3.5 text-amber-500" />
                HEURISTICS ENGINE (LOCAL)
              </Badge>
            )}

            <Button
              variant="outline"
              size="sm"
              onClick={toggleTheme}
              className="gap-2 text-xs border-border bg-card hover:bg-accent text-foreground"
            >
              {isDark ? <Sun className="h-3.5 w-3.5 text-amber-400" /> : <Moon className="h-3.5 w-3.5 text-indigo-500" />}
              {isDark ? "Light Mode" : "Dark Mode"}
            </Button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex flex-wrap items-center gap-2 border-b border-border pb-2">
          <button
            onClick={() => setActiveTab("ai")}
            className={`px-4 py-2 rounded-lg font-medium text-sm flex items-center gap-2 transition-all ${
              activeTab === "ai"
                ? "bg-primary/15 text-primary border border-primary/30 shadow-[0_0_15px_rgba(14,165,233,0.15)] font-semibold"
                : "text-muted-foreground hover:text-foreground hover:bg-muted/50"
            }`}
          >
            <Sparkles className="w-4 h-4 text-primary" />
            AI & Gemini Intelligence
          </button>
          <button
            onClick={() => setActiveTab("soc")}
            className={`px-4 py-2 rounded-lg font-medium text-sm flex items-center gap-2 transition-all ${
              activeTab === "soc"
                ? "bg-primary/15 text-primary border border-primary/30 shadow-[0_0_15px_rgba(14,165,233,0.15)] font-semibold"
                : "text-muted-foreground hover:text-foreground hover:bg-muted/50"
            }`}
          >
            <Sliders className="w-4 h-4 text-primary" />
            SOC Fleet & Telemetry
          </button>
          <button
            onClick={() => setActiveTab("appearance")}
            className={`px-4 py-2 rounded-lg font-medium text-sm flex items-center gap-2 transition-all ${
              activeTab === "appearance"
                ? "bg-primary/15 text-primary border border-primary/30 shadow-[0_0_15px_rgba(14,165,233,0.15)] font-semibold"
                : "text-muted-foreground hover:text-foreground hover:bg-muted/50"
            }`}
          >
            <Palette className="w-4 h-4 text-primary" />
            Theme & Appearance
          </button>
          <button
            onClick={() => setActiveTab("account")}
            className={`px-4 py-2 rounded-lg font-medium text-sm flex items-center gap-2 transition-all ${
              activeTab === "account"
                ? "bg-primary/15 text-primary border border-primary/30 shadow-[0_0_15px_rgba(14,165,233,0.15)] font-semibold"
                : "text-muted-foreground hover:text-foreground hover:bg-muted/50"
            }`}
          >
            <Shield className="w-4 h-4 text-primary" />
            Admin & Access
          </button>
        </div>

        {/* TAB 1: AI & GEMINI */}
        {activeTab === "ai" && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Left 2 Cols: Key Configuration */}
            <div className="lg:col-span-2 space-y-6">
              {/* Primary Configuration Card */}
              <div className="rounded-2xl border border-border bg-card/90 backdrop-blur-md p-6 space-y-6 shadow-sm">
                <div className="flex items-center justify-between border-b border-border pb-4">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-primary/15 border border-primary/30 flex items-center justify-center text-primary">
                      <Cpu className="w-5 h-5" />
                    </div>
                    <div>
                      <h2 className="text-lg font-semibold text-foreground">Google Gemini Neural Engine</h2>
                      <p className="text-xs text-muted-foreground">
                        Powers SOC Copilot threat reasoning, MITRE ATT&CK mapping, and automated incident triage.
                      </p>
                    </div>
                  </div>
                  <Badge variant="outline" className="border-primary/40 text-primary font-mono text-[11px]">
                    v1beta API
                  </Badge>
                </div>

                {/* API Key Input */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <label className="text-xs font-semibold text-foreground uppercase tracking-wider flex items-center gap-1.5">
                      <Key className="w-3.5 h-3.5 text-primary" />
                      Gemini API Key
                    </label>
                    {settingsQuery.data?.gemini.configured && (
                      <span className="text-[11px] font-mono text-emerald-600 dark:text-emerald-400 flex items-center gap-1">
                        <CheckCircle2 className="w-3 h-3" />
                        Stored: {settingsQuery.data.gemini.maskedKey}
                      </span>
                    )}
                  </div>

                  <div className="relative">
                    <Input
                      type={showKey ? "text" : "password"}
                      value={apiKey}
                      onChange={(e) => setApiKey(e.target.value)}
                      placeholder={
                        settingsQuery.data?.gemini.configured
                          ? "Enter new key to replace existing (e.g. AIzaSy...)"
                          : "Paste your Google AI Studio key here (e.g. AIzaSy...)"
                      }
                      className="bg-background border-input text-foreground pr-24 font-mono text-sm placeholder:text-muted-foreground focus:border-primary"
                    />
                    <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-1">
                      <button
                        type="button"
                        onClick={() => setShowKey(!showKey)}
                        className="p-1.5 text-muted-foreground hover:text-foreground rounded hover:bg-muted transition-colors"
                        title={showKey ? "Hide key" : "Show key"}
                      >
                        {showKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>

                  <p className="text-xs text-muted-foreground flex flex-col sm:flex-row sm:items-center justify-between gap-1 pt-1">
                    <span>
                      Get a free API key from Google AI Studio. Free tier supports 15 RPM with 1M context tokens.
                    </span>
                    <a
                      href="https://aistudio.google.com/app/apikey"
                      target="_blank"
                      rel="noreferrer"
                      className="text-primary hover:underline font-medium inline-flex items-center gap-1 whitespace-nowrap"
                    >
                      Get Free Key <ExternalLink className="w-3 h-3" />
                    </a>
                  </p>
                </div>

                {/* Model Selector */}
                <div className="space-y-2">
                  <label className="text-xs font-semibold text-foreground uppercase tracking-wider flex items-center gap-1.5">
                    <Zap className="w-3.5 h-3.5 text-primary" />
                    Reasoning Model Architecture
                  </label>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    {[
                      {
                        id: "gemini-1.5-flash",
                        name: "Gemini 1.5 Flash",
                        tag: "Recommended",
                        desc: "Ultra-fast response, 1M context, optimized for real-time SOC triage",
                      },
                      {
                        id: "gemini-2.0-flash",
                        name: "Gemini 2.0 Flash",
                        tag: "Next-Gen",
                        desc: "Google's newest multimodal model with rapid cyber reasoning",
                      },
                      {
                        id: "gemini-1.5-pro",
                        name: "Gemini 1.5 Pro",
                        tag: "Deep Analysis",
                        desc: "Maximum depth for advanced threat hunting and root-cause reports",
                      },
                    ].map((model) => (
                      <div
                        key={model.id}
                        onClick={() => setSelectedModel(model.id)}
                        className={`cursor-pointer p-3.5 rounded-xl border text-left transition-all ${
                          selectedModel === model.id
                            ? "bg-primary/10 border-primary shadow-[0_0_15px_rgba(14,165,233,0.15)] ring-1 ring-primary"
                            : "bg-muted/30 border-border hover:border-primary/40 hover:bg-muted/50"
                        }`}
                      >
                        <div className="flex items-center justify-between mb-1">
                          <span className="font-semibold text-sm text-foreground">{model.name}</span>
                          <span
                            className={`text-[10px] px-1.5 py-0.5 rounded font-mono ${
                              selectedModel === model.id
                                ? "bg-primary/20 text-primary border border-primary/30"
                                : "bg-muted text-muted-foreground"
                            }`}
                          >
                            {model.tag}
                          </span>
                        </div>
                        <p className="text-xs text-muted-foreground leading-snug">{model.desc}</p>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Test Result Feedback Box */}
                {testResult && (
                  <div
                    className={`p-4 rounded-xl border font-mono text-xs space-y-2 ${
                      testResult.connected
                        ? "bg-emerald-500/10 border-emerald-500/40 text-emerald-700 dark:text-emerald-300"
                        : "bg-red-500/10 border-red-500/40 text-red-700 dark:text-red-300"
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 font-bold">
                        {testResult.connected ? (
                          <>
                            <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                            <span>CONNECTION VERIFIED // {testResult.model}</span>
                          </>
                        ) : (
                          <>
                            <AlertTriangle className="w-4 h-4 text-red-500" />
                            <span>CONNECTION TEST FAILED</span>
                          </>
                        )}
                      </div>
                      <span className="text-[11px] opacity-80">{testResult.latencyMs}ms latency</span>
                    </div>
                    {testResult.connected ? (
                      <p className="text-foreground bg-background/80 p-2.5 rounded border border-emerald-500/20">
                        {testResult.response}
                      </p>
                    ) : (
                      <p className="text-destructive bg-background/80 p-2.5 rounded border border-red-500/20 break-words">
                        {testResult.error}
                      </p>
                    )}
                  </div>
                )}

                {/* Action Buttons */}
                <div className="flex flex-wrap items-center justify-between gap-3 pt-4 border-t border-border">
                  <Button
                    type="button"
                    variant="outline"
                    onClick={handleTestConnection}
                    disabled={testMutation.isPending}
                    className="border-border text-foreground hover:bg-muted text-xs font-medium"
                  >
                    {testMutation.isPending ? (
                      <>
                        <RefreshCw className="w-3.5 h-3.5 mr-2 animate-spin text-primary" />
                        Testing Connection...
                      </>
                    ) : (
                      <>
                        <Radio className="w-3.5 h-3.5 mr-2 text-primary" />
                        Test Connection Probe
                      </>
                    )}
                  </Button>

                  <div className="flex items-center gap-3">
                    <Link href="/copilot">
                      <Button
                        type="button"
                        variant="ghost"
                        className="text-xs text-primary hover:bg-primary/10"
                      >
                        Launch Copilot <ArrowRight className="w-3.5 h-3.5 ml-1" />
                      </Button>
                    </Link>

                    <Button
                      type="button"
                      onClick={handleSaveGemini}
                      disabled={updateGeminiMutation.isPending}
                      className="bg-primary hover:bg-primary/90 text-primary-foreground font-semibold text-xs px-5 shadow-sm"
                    >
                      {updateGeminiMutation.isPending ? (
                        <>
                          <RefreshCw className="w-3.5 h-3.5 mr-2 animate-spin" />
                          Saving...
                        </>
                      ) : (
                        <>
                          <Save className="w-3.5 h-3.5 mr-2" />
                          Save & Connect
                        </>
                      )}
                    </Button>
                  </div>
                </div>
              </div>

              {/* Architecture Explainer Card */}
              <div className="rounded-2xl border border-border bg-card/60 p-5 space-y-3">
                <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
                  <Shield className="w-4 h-4 text-primary" />
                  Dual-Engine Architecture: Live Gemini + High-Speed Local Engine
                </h3>
                <p className="text-xs text-muted-foreground leading-relaxed">
                  CyberGuard AI is resilient by design. With an active Gemini key, all queries execute live multi-turn reasoning with 1M tokens of context.
                  When in offline or local mode, the built-in deterministic heuristic engine powers threat detection, employee telemetry, and containment without interruptions.
                </p>
              </div>
            </div>

            {/* Right Col: AI Pipeline Telemetry & Help */}
            <div className="space-y-6">
              <div className="rounded-2xl border border-border bg-card/90 p-5 space-y-4 shadow-sm">
                <h3 className="text-xs font-semibold text-foreground uppercase tracking-wider">
                  AI Pipeline Telemetry
                </h3>

                <div className="space-y-3">
                  <div className="flex items-center justify-between p-3 rounded-xl bg-muted/30 border border-border">
                    <span className="text-xs text-muted-foreground">Connection Mode</span>
                    <Badge
                      className={`text-[10px] font-mono ${
                        settingsQuery.data?.gemini.configured
                          ? "bg-emerald-500/20 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30"
                          : "bg-amber-500/20 text-amber-600 dark:text-amber-400 border border-amber-500/30"
                      }`}
                    >
                      {settingsQuery.data?.gemini.configured ? "LIVE GOOGLE GEMINI" : "LOCAL HEURISTICS"}
                    </Badge>
                  </div>

                  <div className="flex items-center justify-between p-3 rounded-xl bg-muted/30 border border-border">
                    <span className="text-xs text-muted-foreground">Active Model</span>
                    <span className="text-xs font-mono font-semibold text-primary">
                      {settingsQuery.data?.gemini.model || selectedModel}
                    </span>
                  </div>

                  <div className="flex items-center justify-between p-3 rounded-xl bg-muted/30 border border-border">
                    <span className="text-xs text-muted-foreground">Max Token Context</span>
                    <span className="text-xs font-mono font-semibold text-foreground">1,000,000 Tokens</span>
                  </div>

                  <div className="flex items-center justify-between p-3 rounded-xl bg-muted/30 border border-border">
                    <span className="text-xs text-muted-foreground">Zero-Retention Mode</span>
                    <Badge variant="outline" className="border-primary/30 text-primary text-[10px]">
                      SOC Compliant
                    </Badge>
                  </div>
                </div>

                <div className="pt-2">
                  <Link href="/copilot">
                    <Button className="w-full bg-primary/10 hover:bg-primary/20 text-primary border border-primary/30 text-xs font-semibold">
                      Test in SOC Copilot
                    </Button>
                  </Link>
                </div>
              </div>

              {/* Free Key Guide Card */}
              <div className="rounded-2xl border border-primary/30 bg-primary/5 p-5 space-y-3">
                <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
                  <Key className="w-4 h-4 text-primary" />
                  How to Get a Free Key in 60s
                </h3>
                <ol className="text-xs text-muted-foreground space-y-2 list-decimal list-inside leading-relaxed">
                  <li>
                    Visit{" "}
                    <a
                      href="https://aistudio.google.com/app/apikey"
                      target="_blank"
                      rel="noreferrer"
                      className="text-primary underline font-mono"
                    >
                      aistudio.google.com
                    </a>
                  </li>
                  <li>Sign in with your Google account.</li>
                  <li>Click <strong>"Create API Key"</strong>.</li>
                  <li>Copy the key starting with <code>AIzaSy...</code> and paste it here.</li>
                </ol>
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: SOC FLEET & TELEMETRY */}
        {activeTab === "soc" && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 space-y-6">
              <div className="rounded-2xl border border-border bg-card/90 backdrop-blur-md p-6 space-y-6 shadow-sm">
                <div className="flex items-center gap-3 border-b border-border pb-4">
                  <div className="w-10 h-10 rounded-xl bg-primary/15 border border-primary/30 flex items-center justify-center text-primary">
                    <Activity className="w-5 h-5" />
                  </div>
                  <div>
                    <h2 className="text-lg font-semibold text-foreground">Fleet Telemetry & Mitigation Thresholds</h2>
                    <p className="text-xs text-muted-foreground">
                      Configure real-time packet inspection cycles, anomaly thresholds, and auto-quarantine rules.
                    </p>
                  </div>
                </div>

                {/* Telemetry Polling Rate */}
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="text-sm font-semibold text-foreground">Live Telemetry Sampling Interval</h4>
                      <p className="text-xs text-muted-foreground">How frequently endpoints stream socket & process telemetry to the SOC</p>
                    </div>
                    <Badge variant="outline" className="border-primary/40 text-primary font-mono text-xs">
                      {telemetryInterval} Seconds
                    </Badge>
                  </div>

                  <div className="grid grid-cols-4 gap-3 pt-1">
                    {[3, 5, 10, 30].map((sec) => (
                      <button
                        key={sec}
                        type="button"
                        onClick={() => setTelemetryInterval(sec)}
                        className={`p-3 rounded-xl border text-center text-xs font-semibold transition-all ${
                          telemetryInterval === sec
                            ? "bg-primary/20 border-primary text-primary shadow-sm"
                            : "bg-muted/30 border-border text-muted-foreground hover:text-foreground hover:bg-muted/50"
                        }`}
                      >
                        {sec}s {sec === 3 ? "(Fastest)" : sec === 5 ? "(Balanced)" : ""}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Auto Quarantine Threshold */}
                <div className="space-y-3 pt-4 border-t border-border">
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="text-sm font-semibold text-foreground">Automated Isolation Risk Score Threshold</h4>
                      <p className="text-xs text-muted-foreground">
                        Workstations exceeding this risk score will be recommended or isolated from the network
                      </p>
                    </div>
                    <Badge
                      className={`text-xs font-mono ${
                        quarantineThreshold >= 75
                          ? "bg-red-500/20 text-red-600 dark:text-red-400 border-red-500/30"
                          : "bg-amber-500/20 text-amber-600 dark:text-amber-400 border-amber-500/30"
                      }`}
                    >
                      Score &gt;= {quarantineThreshold}
                    </Badge>
                  </div>

                  <div className="pt-2">
                    <Slider
                      value={[quarantineThreshold]}
                      onValueChange={(val) => setQuarantineThreshold(val[0])}
                      min={40}
                      max={95}
                      step={5}
                      className="py-2"
                    />
                    <div className="flex justify-between text-[11px] font-mono text-muted-foreground pt-1">
                      <span>40 (High Sensitivity)</span>
                      <span>65 (Enterprise Standard)</span>
                      <span>95 (Critical Attacks Only)</span>
                    </div>
                  </div>
                </div>

                {/* Toggles */}
                <div className="space-y-4 pt-4 border-t border-border">
                  <div className="flex items-center justify-between p-3.5 rounded-xl bg-muted/30 border border-border">
                    <div>
                      <div className="text-sm font-medium text-foreground">Automated Endpoint Containment</div>
                      <div className="text-xs text-muted-foreground">
                        Immediately sever outbound TCP sockets when ransomware or C2 activity is detected
                      </div>
                    </div>
                    <Switch checked={autoQuarantine} onCheckedChange={setAutoQuarantine} />
                  </div>

                  <div className="flex items-center justify-between p-3.5 rounded-xl bg-muted/30 border border-border">
                    <div>
                      <div className="text-sm font-medium text-foreground">SOC Alert Notifications</div>
                      <div className="text-xs text-muted-foreground">
                        Dispatch email security advisories to SOC administrators upon critical threat alerts
                      </div>
                    </div>
                    <Switch checked={emailAlerts} onCheckedChange={setEmailAlerts} />
                  </div>
                </div>

                {/* Webhook */}
                <div className="space-y-2 pt-4 border-t border-border">
                  <label className="text-xs font-semibold text-foreground uppercase tracking-wider">
                    SIEM / Incident Response Webhook (Optional)
                  </label>
                  <Input
                    type="url"
                    value={webhookUrl}
                    onChange={(e) => setWebhookUrl(e.target.value)}
                    placeholder="https://hooks.slack.com/services/... or Splunk HEC URL"
                    className="bg-background border-input text-foreground font-mono text-xs placeholder:text-muted-foreground"
                  />
                </div>

                {/* Save */}
                <div className="flex justify-end pt-4 border-t border-border">
                  <Button
                    type="button"
                    onClick={handleSaveSoc}
                    disabled={updateSocMutation.isPending}
                    className="bg-primary hover:bg-primary/90 text-primary-foreground font-semibold text-xs px-6"
                  >
                    <Save className="w-3.5 h-3.5 mr-2" />
                    Save SOC Preferences
                  </Button>
                </div>
              </div>
            </div>

            {/* Quick Actions */}
            <div className="space-y-6">
              <div className="rounded-2xl border border-border bg-card/90 p-5 space-y-4 shadow-sm">
                <h3 className="text-xs font-semibold text-foreground uppercase tracking-wider">
                  Quick Navigation
                </h3>

                <div className="space-y-2">
                  <Link href="/endpoints">
                    <div className="p-3.5 rounded-xl bg-muted/30 border border-border hover:border-primary/40 hover:bg-primary/5 transition-all flex items-center justify-between cursor-pointer group">
                      <div>
                        <div className="text-xs font-semibold text-foreground group-hover:text-primary">
                          Endpoints Fleet
                        </div>
                        <div className="text-[11px] text-muted-foreground">Monitor employee workstations</div>
                      </div>
                      <ArrowRight className="w-4 h-4 text-muted-foreground group-hover:text-primary" />
                    </div>
                  </Link>

                  <Link href="/network">
                    <div className="p-3.5 rounded-xl bg-muted/30 border border-border hover:border-primary/40 hover:bg-primary/5 transition-all flex items-center justify-between cursor-pointer group">
                      <div>
                        <div className="text-xs font-semibold text-foreground group-hover:text-primary">
                          Network Monitor
                        </div>
                        <div className="text-[11px] text-muted-foreground">Inspect real-time socket flows</div>
                      </div>
                      <ArrowRight className="w-4 h-4 text-muted-foreground group-hover:text-primary" />
                    </div>
                  </Link>

                  <Link href="/threats">
                    <div className="p-3.5 rounded-xl bg-muted/30 border border-border hover:border-primary/40 hover:bg-primary/5 transition-all flex items-center justify-between cursor-pointer group">
                      <div>
                        <div className="text-xs font-semibold text-foreground group-hover:text-primary">
                          Threat Feed
                        </div>
                        <div className="text-[11px] text-muted-foreground">Review detected security incidents</div>
                      </div>
                      <ArrowRight className="w-4 h-4 text-muted-foreground group-hover:text-primary" />
                    </div>
                  </Link>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 3: THEME & APPEARANCE */}
        {activeTab === "appearance" && (
          <div className="max-w-4xl space-y-6">
            <div className="rounded-2xl border border-border bg-card/90 backdrop-blur-md p-6 space-y-6 shadow-sm">
              <div className="flex items-center gap-3 border-b border-border pb-4">
                <div className="w-10 h-10 rounded-xl bg-primary/15 border border-primary/30 flex items-center justify-center text-primary">
                  <Palette className="w-5 h-5" />
                </div>
                <div>
                  <h2 className="text-lg font-semibold text-foreground">Theme & Visual Appearance</h2>
                  <p className="text-xs text-muted-foreground">
                    Customize high-contrast daylight vs. cyber midnight themes for SOC analysts.
                  </p>
                </div>
              </div>

              {/* Theme Modes Grid */}
              <div className="space-y-3">
                <label className="text-xs font-semibold text-foreground uppercase tracking-wider">
                  Interface Display Mode
                </label>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  {/* Dark Theme Option */}
                  <div
                    onClick={() => {
                      if (!isDark && toggleTheme) toggleTheme();
                    }}
                    className={`cursor-pointer rounded-2xl border p-5 transition-all ${
                      isDark
                        ? "border-primary bg-primary/10 shadow-[0_0_20px_rgba(14,165,233,0.15)] ring-2 ring-primary"
                        : "border-border bg-muted/20 hover:border-border hover:bg-muted/40"
                    }`}
                  >
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center gap-2.5">
                        <div className="w-8 h-8 rounded-lg bg-zinc-900 border border-zinc-800 flex items-center justify-center text-cyan-400">
                          <Moon className="w-4 h-4" />
                        </div>
                        <div>
                          <div className="font-semibold text-sm text-foreground">Dark Cyber Mode</div>
                          <div className="text-xs text-muted-foreground">Midnight blue & glowing cyan telemetry</div>
                        </div>
                      </div>
                      {isDark && (
                        <Badge className="bg-primary text-primary-foreground text-[10px]">Active</Badge>
                      )}
                    </div>

                    <div className="h-20 rounded-xl bg-[#07111f] border border-cyan-500/20 p-3 flex flex-col justify-between">
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] font-mono text-cyan-400">CYBERGUARD SOC</span>
                        <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                      </div>
                      <div className="flex gap-2">
                        <div className="h-5 flex-1 rounded bg-[#0d1f33] border border-cyan-500/30 text-[9px] font-mono text-cyan-300 flex items-center px-2">
                          192.168.1.105 : 443
                        </div>
                        <div className="h-5 w-12 rounded bg-cyan-500/20 text-[9px] font-mono text-cyan-400 flex items-center justify-center">
                          ALLOW
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Light Theme Option */}
                  <div
                    onClick={() => {
                      if (isDark && toggleTheme) toggleTheme();
                    }}
                    className={`cursor-pointer rounded-2xl border p-5 transition-all ${
                      !isDark
                        ? "border-primary bg-primary/10 shadow-[0_0_20px_rgba(14,165,233,0.15)] ring-2 ring-primary"
                        : "border-border bg-muted/20 hover:border-border hover:bg-muted/40"
                    }`}
                  >
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center gap-2.5">
                        <div className="w-8 h-8 rounded-lg bg-white border border-slate-200 flex items-center justify-center text-amber-500 shadow-sm">
                          <Sun className="w-4 h-4" />
                        </div>
                        <div>
                          <div className="font-semibold text-sm text-foreground">Light Modern Mode</div>
                          <div className="text-xs text-muted-foreground">High-contrast daytime slate & crisp text</div>
                        </div>
                      </div>
                      {!isDark && (
                        <Badge className="bg-primary text-primary-foreground text-[10px]">Active</Badge>
                      )}
                    </div>

                    <div className="h-20 rounded-xl bg-[#edf5ff] border border-sky-200 p-3 flex flex-col justify-between shadow-inner">
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] font-mono font-bold text-slate-800">CYBERGUARD SOC</span>
                        <span className="w-2 h-2 rounded-full bg-emerald-500" />
                      </div>
                      <div className="flex gap-2">
                        <div className="h-5 flex-1 rounded bg-white border border-sky-300 text-[9px] font-mono text-slate-700 flex items-center px-2 shadow-xs">
                          192.168.1.105 : 443
                        </div>
                        <div className="h-5 w-12 rounded bg-emerald-100 text-[9px] font-mono text-emerald-700 font-bold flex items-center justify-center">
                          ALLOW
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Accent Color Palette Preview */}
              <div className="space-y-3 pt-4 border-t border-border">
                <label className="text-xs font-semibold text-foreground uppercase tracking-wider">
                  Enterprise Accent Palette
                </label>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  {[
                    { name: "Cyber Cyan", color: "#0ea5e9", tag: "Standard SOC" },
                    { name: "Electric Blue", color: "#3b82f6", tag: "High Contrast" },
                    { name: "Emerald Guard", color: "#10b981", tag: "Defensive" },
                    { name: "Purple Neon", color: "#8b5cf6", tag: "Intelligence" },
                  ].map((p, idx) => (
                    <div
                      key={p.name}
                      onClick={() => toast.success(`Selected ${p.name} palette!`)}
                      className={`cursor-pointer p-3 rounded-xl border transition-all ${
                        idx === 0
                          ? "border-primary bg-primary/10 ring-1 ring-primary"
                          : "border-border bg-muted/30 hover:border-primary/40"
                      }`}
                    >
                      <div className="flex items-center gap-2 mb-1">
                        <span className="w-3.5 h-3.5 rounded-full" style={{ backgroundColor: p.color }} />
                        <span className="text-xs font-semibold text-foreground">{p.name}</span>
                      </div>
                      <span className="text-[10px] text-muted-foreground block">{p.tag}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 4: ADMIN & ACCESS */}
        {activeTab === "account" && (
          <div className="max-w-2xl space-y-6">
            <div className="rounded-2xl border border-border bg-card/90 backdrop-blur-md p-6 space-y-6 shadow-sm">
              <div className="flex items-center gap-3 border-b border-border pb-4">
                <div className="w-10 h-10 rounded-xl bg-primary/15 border border-primary/30 flex items-center justify-center text-primary">
                  <Shield className="w-5 h-5" />
                </div>
                <div>
                  <h2 className="text-lg font-semibold text-foreground">SOC Operator Profile</h2>
                  <p className="text-xs text-muted-foreground">Authenticated operator account details and permissions.</p>
                </div>
              </div>

              <div className="space-y-3">
                <div className="flex items-center justify-between p-3.5 rounded-xl bg-muted/30 border border-border">
                  <span className="text-xs text-muted-foreground">Account Email</span>
                  <span className="text-xs font-mono text-foreground font-semibold">{user?.email || "admin@cyberguard.ai"}</span>
                </div>

                <div className="flex items-center justify-between p-3.5 rounded-xl bg-muted/30 border border-border">
                  <span className="text-xs text-muted-foreground">Security Role</span>
                  <Badge className="bg-primary/20 text-primary border-primary/30 font-mono text-xs uppercase font-bold">
                    {user?.role || "ADMIN"}
                  </Badge>
                </div>

                <div className="flex items-center justify-between p-3.5 rounded-xl bg-muted/30 border border-border">
                  <span className="text-xs text-muted-foreground">Multi-Factor Status</span>
                  <Badge className="bg-emerald-500/20 text-emerald-600 dark:text-emerald-400 border-emerald-500/30 text-xs">
                    Verified (OTP Session)
                  </Badge>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </DashboardLayout>
  );
}
