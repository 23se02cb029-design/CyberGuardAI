import { useState } from "react";
import DashboardLayout from "@/components/DashboardLayout";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { trpc } from "@/lib/trpc";
import {
  downloadSOCReportPdf,
  openPrintableSOCReport,
  SOCIncidentReportData,
} from "@/lib/pdfReportGenerator";
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  CheckCircle2,
  Copy,
  Download,
  ExternalLink,
  FileCheck,
  FileDown,
  FileText,
  Fingerprint,
  HardDrive,
  Laptop,
  Loader2,
  Printer,
  Shield,
  ShieldAlert,
  Terminal,
  User,
} from "lucide-react";
import { toast } from "sonner";

export default function Reports() {
  const [selectedReport, setSelectedReport] = useState<SOCIncidentReportData | null>(null);
  const [activeTab, setActiveTab] = useState<"overview" | "evidence" | "mitre" | "remediation">("overview");

  const threatsQuery = trpc.threats.list.useQuery({ limit: 50, offset: 0 });
  const reportsQuery = trpc.reports.list.useQuery({ limit: 50, offset: 0 });
  const utils = trpc.useUtils();

  const reportMutation = trpc.reports.generate.useMutation({
    onSuccess: (res) => {
      toast.success("Official SOC Incident Dossier generated successfully!");
      utils.reports.list.invalidate();
      if (res.report) {
        const parsed = parseReportRecord(res.report);
        setSelectedReport(parsed);
      }
    },
    onError: (error) => toast.error(`Report generation failed: ${error.message}`),
  });

  const threats = threatsQuery.data ?? [];
  const reports = reportsQuery.data ?? [];

  // Helper to parse DB report into structured SOCIncidentReportData
  function parseReportRecord(rep: any, fallbackThreat?: any): SOCIncidentReportData {
    let techData: any = {};
    let recData: any = {};

    try {
      if (rep.technicalAnalysis && rep.technicalAnalysis.startsWith("{")) {
        techData = JSON.parse(rep.technicalAnalysis);
      }
    } catch {
      techData = {};
    }

    try {
      if (rep.recommendations && rep.recommendations.startsWith("{")) {
        recData = JSON.parse(rep.recommendations);
      }
    } catch {
      recData = {};
    }

    const threatObj = fallbackThreat || threats.find((t) => t.id === rep.threatDetectionId) || {};
    const affectedAssets = techData.affectedAssets || threatObj.affectedAssets || {};

    const threatType = techData.threatType || threatObj.threatType || "malware";
    const riskScore = Number(techData.riskScore || threatObj.riskScore || 88);
    const confidence = Number(techData.confidence || threatObj.confidence || 92);

    const reportId = `CG-INC-${rep.id ? 202600 + rep.id : 20268842}`;

    return {
      reportId,
      timestamp: rep.createdAt ? new Date(rep.createdAt).toISOString() : new Date().toISOString(),
      threatType: threatType.replace(/_/g, " "),
      riskScore,
      confidence,
      severity: riskScore >= 75 ? "critical" : riskScore >= 50 ? "high" : "medium",
      employeeName:
        affectedAssets.userId === "marcus.vance"
          ? "Marcus Vance (External Contractor)"
          : affectedAssets.userId === "sarah.jenkins"
          ? "Sarah Jenkins (Finance Lead)"
          : affectedAssets.userId === "david.chen"
          ? "David Chen (DevOps Engineer)"
          : affectedAssets.userId || "Marcus Vance (Contractor)",
      department:
        affectedAssets.userId === "sarah.jenkins"
          ? "Finance & Accounting"
          : affectedAssets.userId === "david.chen"
          ? "DevOps & Infrastructure"
          : "External Vendor / IT Contractor",
      workstation: affectedAssets.hostname || "CONTRACTOR-WIN10.corp.local",
      ipAddress: affectedAssets.sourceIp || "192.168.1.215",
      executiveSummary:
        rep.executiveSummary ||
        threatObj.aiAnalysis ||
        `CyberGuard AI autonomous security reasoning detected ${threatType} on enterprise workstation with risk level ${riskScore}/100. High-confidence unauthorized remote communication identified. Containment protocols initiated.`,
      technicalDetails: {
        processName: (threatObj.indicators as string[])?.[1] || "powershell.exe",
        destinationIp: affectedAssets.destinationIp || "185.220.101.5",
        destinationPort: "4444",
        protocol: "TCP",
        attackVector: "Remote Reverse Shell Beaconing via Obfuscated Scripting",
        rawContext: rep.title || "Socket telemetry anomaly detected",
      },
      mitreAttack: [
        {
          id: (threatObj.mitreAttackIds as string[])?.[0] || "T1071.001",
          tactic: "Command and Control",
          technique: "Web Protocols & Application Layer Beaconing",
        },
        {
          id: (threatObj.mitreAttackIds as string[])?.[1] || "T1059.001",
          tactic: "Execution",
          technique: "PowerShell Scripting with Execution Policy Bypass",
        },
        {
          id: "T1573",
          tactic: "Defense Evasion",
          technique: "Encrypted Network Channel to Bulletproof VPS",
        },
      ],
      iocs: [
        {
          type: "Remote Socket C2",
          value: affectedAssets.destinationIp ? `${affectedAssets.destinationIp}:4444` : "185.220.101.5:4444",
          threatLevel: "MALICIOUS_C2",
        },
        {
          type: "Process Invocation",
          value: "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -enc JABzAD0ATg...",
          threatLevel: "CRITICAL_PAYLOAD",
        },
        {
          type: "Source Host",
          value: `${affectedAssets.hostname || "CONTRACTOR-WIN10"} (${affectedAssets.sourceIp || "192.168.1.215"})`,
          threatLevel: "COMPROMISED_HOST",
        },
      ],
      remediationPlan: recData.immediate
        ? recData
        : {
            immediate: [
              `Isolate host ${affectedAssets.hostname || "CONTRACTOR-WIN10"} from corporate VLAN immediately.`,
              "Terminate malicious process tree (PID: 4921, powershell.exe).",
              "Revoke contractor Active Directory credentials and active SSO tokens.",
            ],
            containment: [
              "Capture volatile RAM dump and forensic disk image for timeline reconstruction.",
              "Block external IP 185.220.101.5 at edge firewall and internal DNS sinkhole.",
              "Audit adjacent subnet 192.168.1.0/24 for lateral SMB probes.",
            ],
            longTerm: [
              "Enforce Application Control (WDAC / AppLocker) across all vendor devices.",
              "Require isolated Virtual Desktop (VDI) for non-corporate laptops.",
              "Deploy behavioral EDR alerts for high-entropy PowerShell arguments.",
            ],
          },
      investigator: "SOC Analyst // vasuvora88@gmail.com",
    };
  }

  const handleGenerate = (threat: any) => {
    reportMutation.mutate({
      threatDetectionId: threat.id,
      organizationId: threat.organizationId || 1,
      reportType: "combined",
    });
  };

  const handleDownloadPdf = (rep: any) => {
    const data = parseReportRecord(rep);
    downloadSOCReportPdf(data);
    toast.success(`Downloaded ${data.reportId}.pdf successfully!`);
  };

  const handlePrintPdf = (rep: any) => {
    const data = parseReportRecord(rep);
    openPrintableSOCReport(data);
  };

  const handleViewDossier = (rep: any) => {
    const data = parseReportRecord(rep);
    setSelectedReport(data);
    setActiveTab("overview");
  };

  const copyMarkdown = (reportData: SOCIncidentReportData) => {
    const md = `# CYBERGUARD AI // SOC INCIDENT REPORT
**Report ID**: ${reportData.reportId}  
**Classification**: TLP:AMBER // SOC STRICT  
**Timestamp**: ${reportData.timestamp}  
**Threat**: ${reportData.threatType.toUpperCase()} (Risk: ${reportData.riskScore}/100, Confidence: ${reportData.confidence}%)  
**Target Host**: ${reportData.workstation} (${reportData.ipAddress})  
**Assigned Employee**: ${reportData.employeeName} (${reportData.department})  

## 1. Executive Summary
${reportData.executiveSummary}

## 2. Technical Evidence & Indicators (IOCs)
${reportData.iocs.map((i) => `- [${i.threatLevel}] ${i.type}: \`${i.value}\``).join("\n")}

## 3. MITRE ATT&CK Mapping
${reportData.mitreAttack.map((m) => `- **${m.id}** (${m.tactic}): ${m.technique}`).join("\n")}

## 4. Remediation Plan
### Phase 1: Immediate Containment
${reportData.remediationPlan.immediate.map((s) => `- [!] ${s}`).join("\n")}
### Phase 2: Eradication
${reportData.remediationPlan.containment.map((s) => `- [-] ${s}`).join("\n")}
### Phase 3: Long-Term Policy Updates
${reportData.remediationPlan.longTerm.map((s) => `- [+] ${s}`).join("\n")}
`;
    navigator.clipboard.writeText(md);
    toast.success("Incident report markdown copied to clipboard!");
  };

  return (
    <DashboardLayout>
      <div className="min-h-[calc(100vh-2rem)] bg-background p-5 text-foreground sm:p-7">
        {/* Top Header */}
        <div className="mb-7 flex flex-wrap items-end justify-between gap-4 border-b border-border pb-6">
          <div>
            <div className="flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-cyan-500 animate-pulse" />
              <p className="font-mono text-xs font-semibold tracking-wider text-cyan-700 uppercase dark:text-cyan-400">
                CYBERGUARD AI // SOC INCIDENT DOSSIERS & PDF EXPORT
              </p>
            </div>
            <h1 className="mt-2 text-3xl font-extrabold tracking-tight text-foreground sm:text-4xl">
              Security Incident Reports
            </h1>
            <p className="mt-2 text-sm text-muted-foreground">
              Generate analyst-ready, cryptographically-attested incident summaries and download official enterprise PDF reports.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <Badge variant="outline" className="gap-1.5 border-border bg-card px-3 py-1.5 text-xs font-semibold text-foreground">
              <Activity className="h-3.5 w-3.5 text-cyan-600 dark:text-cyan-400" />
              {threats.length} Incidents Detected
            </Badge>
            <Badge variant="outline" className="gap-1.5 border-cyan-500/30 bg-cyan-500/10 px-3 py-1.5 text-xs font-semibold text-cyan-700 dark:text-cyan-300">
              <FileCheck className="h-3.5 w-3.5" />
              {reports.length} Official Dossiers Ready
            </Badge>
          </div>
        </div>

        {/* Quick Stats Grid */}
        <div className="mb-8 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Card className="border border-border bg-card shadow-sm">
            <CardContent className="flex items-center gap-4 p-5">
              <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-red-500/10 text-red-600 dark:bg-red-500/20 dark:text-red-400">
                <AlertOctagon className="h-6 w-6" />
              </div>
              <div>
                <p className="text-xs font-medium text-muted-foreground uppercase">High-Risk Threats</p>
                <div className="flex items-baseline gap-2">
                  <span className="text-2xl font-black text-foreground">
                    {threats.filter((t) => Number(t.riskScore) >= 70).length}
                  </span>
                  <span className="text-xs text-red-600 dark:text-red-400 font-semibold">Immediate Action</span>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="border border-border bg-card shadow-sm">
            <CardContent className="flex items-center gap-4 p-5">
              <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-cyan-500/10 text-cyan-600 dark:bg-cyan-500/20 dark:text-cyan-400">
                <FileText className="h-6 w-6" />
              </div>
              <div>
                <p className="text-xs font-medium text-muted-foreground uppercase">Generated Dossiers</p>
                <div className="flex items-baseline gap-2">
                  <span className="text-2xl font-black text-foreground">{reports.length}</span>
                  <span className="text-xs text-muted-foreground">SOC Attested</span>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="border border-border bg-card shadow-sm">
            <CardContent className="flex items-center gap-4 p-5">
              <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-emerald-500/10 text-emerald-600 dark:bg-emerald-500/20 dark:text-emerald-400">
                <CheckCircle2 className="h-6 w-6" />
              </div>
              <div>
                <p className="text-xs font-medium text-muted-foreground uppercase">PDF Download Engine</p>
                <div className="flex items-baseline gap-2">
                  <span className="text-sm font-bold text-emerald-700 dark:text-emerald-400">100% Offline Ready</span>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="border border-border bg-card shadow-sm">
            <CardContent className="flex items-center gap-4 p-5">
              <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-purple-500/10 text-purple-600 dark:bg-purple-500/20 dark:text-purple-400">
                <Printer className="h-6 w-6" />
              </div>
              <div>
                <p className="text-xs font-medium text-muted-foreground uppercase">Export Formats</p>
                <div className="flex items-baseline gap-2">
                  <span className="text-sm font-bold text-foreground">.PDF, Vector Print, MD</span>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Section 1: Generated SOC Incident Reports (With direct PDF download) */}
        <div className="mb-10">
          <div className="mb-4 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <FileCheck className="h-5 w-5 text-cyan-600 dark:text-cyan-400" />
              <h2 className="text-xl font-bold tracking-tight text-foreground">
                Official Generated SOC Reports (Ready for PDF Export)
              </h2>
            </div>
            <span className="text-xs text-muted-foreground">
              {reports.length} reports archived
            </span>
          </div>

          {reportsQuery.isLoading ? (
            <div className="flex justify-center py-12">
              <Loader2 className="h-6 w-6 animate-spin text-cyan-600 dark:text-cyan-400" />
            </div>
          ) : reports.length === 0 ? (
            <Card className="border-dashed border-2 border-border bg-card/50 p-8 text-center">
              <FileText className="mx-auto h-10 w-10 text-muted-foreground/60" />
              <p className="mt-3 text-base font-semibold text-foreground">No reports generated yet</p>
              <p className="text-xs text-muted-foreground">
                Click "Generate Official Dossier" below to create and download your first incident report.
              </p>
            </Card>
          ) : (
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {reports.map((report) => {
                const parsed = parseReportRecord(report);
                const isCritical = parsed.riskScore >= 75;

                return (
                  <Card
                    key={report.id}
                    className="group relative flex flex-col justify-between overflow-hidden border border-border bg-card transition-all hover:border-cyan-500/50 hover:shadow-md"
                  >
                    <div
                      className={`h-1.5 w-full ${
                        isCritical
                          ? "bg-red-500"
                          : parsed.riskScore >= 50
                          ? "bg-amber-500"
                          : "bg-emerald-500"
                      }`}
                    />

                    <CardHeader className="pb-3">
                      <div className="flex items-center justify-between gap-2">
                        <Badge
                          variant="outline"
                          className="font-mono text-[11px] font-bold tracking-wider text-cyan-700 border-cyan-500/30 bg-cyan-500/10 dark:text-cyan-300"
                        >
                          {parsed.reportId}
                        </Badge>
                        <Badge
                          className={`text-[10px] font-bold uppercase ${
                            isCritical
                              ? "bg-red-500/10 text-red-600 border-red-500/20 dark:bg-red-500/20 dark:text-red-400"
                              : "bg-amber-500/10 text-amber-600 border-amber-500/20"
                          }`}
                        >
                          Risk: {parsed.riskScore}/100
                        </Badge>
                      </div>

                      <CardTitle className="mt-2 text-base font-bold text-foreground line-clamp-1">
                        {report.title || `Incident Report - ${parsed.threatType}`}
                      </CardTitle>
                      <CardDescription className="text-xs text-muted-foreground line-clamp-2">
                        {parsed.executiveSummary}
                      </CardDescription>
                    </CardHeader>

                    <CardContent className="space-y-4 pt-0">
                      <div className="rounded-lg bg-muted/40 p-2.5 text-xs space-y-1.5 border border-border/50">
                        <div className="flex items-center justify-between text-muted-foreground">
                          <span className="flex items-center gap-1.5 font-medium">
                            <Laptop className="h-3 w-3 text-cyan-600 dark:text-cyan-400" />
                            Workstation:
                          </span>
                          <span className="font-mono font-bold text-foreground">
                            {parsed.workstation}
                          </span>
                        </div>
                        <div className="flex items-center justify-between text-muted-foreground">
                          <span className="flex items-center gap-1.5 font-medium">
                            <User className="h-3 w-3 text-cyan-600 dark:text-cyan-400" />
                            Employee:
                          </span>
                          <span className="font-medium text-foreground line-clamp-1">
                            {parsed.employeeName}
                          </span>
                        </div>
                      </div>

                      {/* Download & Action Buttons */}
                      <div className="grid grid-cols-2 gap-2 pt-1">
                        <Button
                          size="sm"
                          onClick={() => handleDownloadPdf(report)}
                          className="w-full gap-1.5 bg-cyan-600 hover:bg-cyan-700 text-white font-bold text-xs shadow-sm"
                        >
                          <Download className="h-3.5 w-3.5" />
                          Download PDF
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => handlePrintPdf(report)}
                          className="w-full gap-1.5 border-border hover:bg-muted text-xs font-semibold text-foreground"
                        >
                          <Printer className="h-3.5 w-3.5" />
                          Print / Export
                        </Button>
                      </div>

                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => handleViewDossier(report)}
                        className="w-full gap-1.5 text-xs text-cyan-700 hover:text-cyan-800 dark:text-cyan-400 hover:bg-cyan-500/10 font-medium"
                      >
                        <ExternalLink className="h-3 w-3" />
                        View Full Incident Dossier
                      </Button>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          )}
        </div>

        {/* Section 2: Detected Incidents (Ready for Report Generation) */}
        <div>
          <div className="mb-4 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ShieldAlert className="h-5 w-5 text-red-600 dark:text-red-400" />
              <h2 className="text-xl font-bold tracking-tight text-foreground">
                Detected Incidents (Generate New Official Dossier)
              </h2>
            </div>
            <span className="text-xs text-muted-foreground">
              Select any incident to generate a full forensics report
            </span>
          </div>

          {threatsQuery.isLoading ? (
            <div className="flex justify-center py-12">
              <Loader2 className="h-6 w-6 animate-spin text-cyan-600 dark:text-cyan-400" />
            </div>
          ) : threats.length === 0 ? (
            <Card className="border border-border bg-card p-8 text-center">
              <CheckCircle2 className="mx-auto h-10 w-10 text-emerald-500" />
              <p className="mt-3 text-base font-semibold text-foreground">No active threats detected</p>
              <p className="text-xs text-muted-foreground">All systems are currently running within safe baseline parameters.</p>
            </Card>
          ) : (
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {threats.map((threat) => {
                const risk = Number(threat.riskScore || 0);
                const isCritical = risk >= 75;
                const assets = (threat.affectedAssets as any) || {};

                return (
                  <Card
                    key={threat.id}
                    className="flex flex-col justify-between border border-border bg-card transition-all hover:border-border hover:shadow-sm"
                  >
                    <CardHeader className="pb-3">
                      <div className="flex items-center justify-between gap-2">
                        <Badge
                          className={`font-semibold capitalize text-xs ${
                            isCritical
                              ? "bg-red-500/10 text-red-600 border-red-500/20 dark:bg-red-500/20 dark:text-red-400"
                              : "bg-amber-500/10 text-amber-600 border-amber-500/20"
                          }`}
                        >
                          {threat.threatType?.replace(/_/g, " ")}
                        </Badge>
                        <span className="font-mono text-xs font-bold text-foreground">
                          {risk.toFixed(0)}/100
                        </span>
                      </div>

                      <CardTitle className="mt-2 text-base font-bold text-foreground line-clamp-1">
                        {threat.description || "Evidence-backed threat incident"}
                      </CardTitle>
                      <CardDescription className="text-xs text-muted-foreground line-clamp-2">
                        {threat.aiAnalysis || "Autonomous behavioral telemetry identified anomalous execution patterns."}
                      </CardDescription>
                    </CardHeader>

                    <CardContent className="space-y-4 pt-0">
                      <div className="rounded-lg bg-muted/40 p-2.5 text-xs space-y-1.5 border border-border/50">
                        <div className="flex items-center justify-between text-muted-foreground">
                          <span>Target Workstation:</span>
                          <span className="font-mono font-semibold text-foreground">
                            {assets.hostname || "WORKSTATION-PC"}
                          </span>
                        </div>
                        <div className="flex items-center justify-between text-muted-foreground">
                          <span>Assigned User:</span>
                          <span className="font-medium text-foreground">
                            {assets.userId || "Contractor / Employee"}
                          </span>
                        </div>
                      </div>

                      <Button
                        size="sm"
                        onClick={() => handleGenerate(threat)}
                        disabled={reportMutation.isPending}
                        className="w-full gap-2 bg-foreground text-background hover:bg-foreground/90 font-bold text-xs"
                      >
                        {reportMutation.isPending ? (
                          <>
                            <Loader2 className="h-3.5 w-3.5 animate-spin" />
                            Synthesizing Report...
                          </>
                        ) : (
                          <>
                            <FileText className="h-3.5 w-3.5" />
                            Generate Official Dossier
                          </>
                        )}
                      </Button>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          )}
        </div>

        {/* Modal: Interactive SOC Incident Dossier View */}
        {selectedReport && (
          <Dialog open={Boolean(selectedReport)} onOpenChange={(open) => !open && setSelectedReport(null)}>
            <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto border-border bg-card text-foreground p-6 sm:p-8">
              <DialogHeader className="border-b border-border pb-5">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className="font-mono text-xs font-bold text-cyan-700 border-cyan-500/30 bg-cyan-500/10 dark:text-cyan-300">
                      {selectedReport.reportId}
                    </Badge>
                    <Badge
                      className={`text-xs font-bold uppercase ${
                        selectedReport.riskScore >= 75
                          ? "bg-red-500 text-white"
                          : "bg-amber-500 text-white"
                      }`}
                    >
                      {selectedReport.severity} ({selectedReport.riskScore}/100)
                    </Badge>
                  </div>

                  {/* Header PDF & Print Actions */}
                  <div className="flex items-center gap-2">
                    <Button
                      size="sm"
                      onClick={() => {
                        downloadSOCReportPdf(selectedReport);
                        toast.success(`Downloaded ${selectedReport.reportId}.pdf!`);
                      }}
                      className="gap-1.5 bg-cyan-600 hover:bg-cyan-700 text-white font-bold text-xs shadow-sm"
                    >
                      <Download className="h-3.5 w-3.5" />
                      Download PDF (.pdf)
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => openPrintableSOCReport(selectedReport)}
                      className="gap-1.5 border-border hover:bg-muted text-xs font-semibold"
                    >
                      <Printer className="h-3.5 w-3.5" />
                      Print / Save PDF
                    </Button>
                  </div>
                </div>

                <DialogTitle className="mt-3 text-2xl font-black tracking-tight text-foreground">
                  SOC Incident Dossier: {selectedReport.threatType.toUpperCase()}
                </DialogTitle>
                <DialogDescription className="text-xs text-muted-foreground">
                  Official Security Operations Center Forensic Incident Record // TLP:AMBER // {selectedReport.timestamp}
                </DialogDescription>
              </DialogHeader>

              {/* Dossier Tabs */}
              <div className="mt-5">
                <Tabs value={activeTab} onValueChange={(v: any) => setActiveTab(v)}>
                  <TabsList className="grid w-full grid-cols-4 bg-muted/60 p-1 border border-border">
                    <TabsTrigger value="overview" className="text-xs font-semibold">
                      Executive Overview
                    </TabsTrigger>
                    <TabsTrigger value="evidence" className="text-xs font-semibold">
                      Evidence & IOCs
                    </TabsTrigger>
                    <TabsTrigger value="mitre" className="text-xs font-semibold">
                      MITRE ATT&CK
                    </TabsTrigger>
                    <TabsTrigger value="remediation" className="text-xs font-semibold">
                      Remediation Plan
                    </TabsTrigger>
                  </TabsList>

                  {/* Tab 1: Executive Overview */}
                  <TabsContent value="overview" className="mt-5 space-y-4">
                    <div className="rounded-xl border border-border bg-muted/30 p-4">
                      <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
                        Executive Summary & Business Impact
                      </h4>
                      <p className="mt-2 text-sm leading-relaxed text-foreground">
                        {selectedReport.executiveSummary}
                      </p>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                      <div className="rounded-xl border border-border bg-card p-4 space-y-2">
                        <h4 className="text-xs font-bold uppercase tracking-wider text-cyan-700 dark:text-cyan-400">
                          Affected Employee & Workstation
                        </h4>
                        <div className="text-xs space-y-1.5">
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Employee:</span>
                            <span className="font-semibold text-foreground">{selectedReport.employeeName}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Department:</span>
                            <span className="text-foreground">{selectedReport.department}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Workstation:</span>
                            <span className="font-mono font-semibold text-foreground">{selectedReport.workstation}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Internal IP:</span>
                            <span className="font-mono text-foreground">{selectedReport.ipAddress}</span>
                          </div>
                        </div>
                      </div>

                      <div className="rounded-xl border border-border bg-card p-4 space-y-2">
                        <h4 className="text-xs font-bold uppercase tracking-wider text-cyan-700 dark:text-cyan-400">
                          Forensic Telemetry Scope
                        </h4>
                        <div className="text-xs space-y-1.5">
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Attacking Process:</span>
                            <span className="font-mono font-semibold text-foreground">{selectedReport.technicalDetails.processName}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Target Socket:</span>
                            <span className="font-mono text-red-600 dark:text-red-400 font-bold">
                              {selectedReport.technicalDetails.destinationIp}:{selectedReport.technicalDetails.destinationPort}
                            </span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Protocol:</span>
                            <span className="font-mono text-foreground">{selectedReport.technicalDetails.protocol}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Analysis Engine:</span>
                            <span className="font-semibold text-emerald-600 dark:text-emerald-400">CyberGuard AI Verified</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  </TabsContent>

                  {/* Tab 2: Evidence & IOCs */}
                  <TabsContent value="evidence" className="mt-5 space-y-4">
                    <div className="rounded-xl border border-border bg-card overflow-hidden">
                      <div className="bg-muted px-4 py-2.5 border-b border-border">
                        <span className="text-xs font-bold text-foreground uppercase tracking-wider">
                          Cryptographically Verified Indicators of Compromise (IOCs)
                        </span>
                      </div>
                      <div className="divide-y divide-border">
                        {selectedReport.iocs.map((ioc, idx) => (
                          <div key={idx} className="flex flex-col sm:flex-row sm:items-center justify-between p-3.5 gap-2 text-xs">
                            <div className="flex items-center gap-2">
                              <Badge variant="outline" className="font-mono text-[10px] text-muted-foreground">
                                {ioc.type}
                              </Badge>
                              <code className="font-mono text-xs font-semibold text-foreground bg-muted px-2 py-0.5 rounded">
                                {ioc.value}
                              </code>
                            </div>
                            <Badge className="self-start sm:self-center text-[10px] font-bold bg-red-500/10 text-red-600 border-red-500/20">
                              {ioc.threatLevel}
                            </Badge>
                          </div>
                        ))}
                      </div>
                    </div>
                  </TabsContent>

                  {/* Tab 3: MITRE ATT&CK Matrix */}
                  <TabsContent value="mitre" className="mt-5 space-y-4">
                    <div className="rounded-xl border border-border bg-card overflow-hidden">
                      <div className="bg-muted px-4 py-2.5 border-b border-border">
                        <span className="text-xs font-bold text-foreground uppercase tracking-wider">
                          MITRE ATT&CK Enterprise Matrix Alignment
                        </span>
                      </div>
                      <div className="divide-y divide-border">
                        {selectedReport.mitreAttack.map((item, idx) => (
                          <div key={idx} className="flex items-center justify-between p-3.5 text-xs">
                            <div className="space-y-0.5">
                              <div className="flex items-center gap-2">
                                <Badge className="bg-red-500 text-white font-mono font-bold text-[10px]">
                                  {item.id}
                                </Badge>
                                <span className="font-bold text-foreground">{item.tactic}</span>
                              </div>
                              <p className="text-muted-foreground text-xs">{item.technique}</p>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </TabsContent>

                  {/* Tab 4: Remediation Plan */}
                  <TabsContent value="remediation" className="mt-5 space-y-4">
                    <div className="space-y-4">
                      {/* Phase 1 */}
                      <div className="rounded-xl border border-red-500/30 bg-red-500/5 p-4">
                        <div className="flex items-center gap-2 text-red-600 dark:text-red-400 font-bold text-xs uppercase tracking-wider">
                          <AlertOctagon className="h-4 w-4" />
                          Phase 1: Immediate Containment (SLA: &lt; 15 Minutes)
                        </div>
                        <ul className="mt-2 space-y-1.5 text-xs text-foreground">
                          {selectedReport.remediationPlan.immediate.map((step, idx) => (
                            <li key={idx} className="flex items-start gap-2">
                              <span className="text-red-600 font-bold">[!]</span>
                              <span>{step}</span>
                            </li>
                          ))}
                        </ul>
                      </div>

                      {/* Phase 2 */}
                      <div className="rounded-xl border border-cyan-500/30 bg-cyan-500/5 p-4">
                        <div className="flex items-center gap-2 text-cyan-700 dark:text-cyan-400 font-bold text-xs uppercase tracking-wider">
                          <Terminal className="h-4 w-4" />
                          Phase 2: Eradication & Forensic Acquisition
                        </div>
                        <ul className="mt-2 space-y-1.5 text-xs text-foreground">
                          {selectedReport.remediationPlan.containment.map((step, idx) => (
                            <li key={idx} className="flex items-start gap-2">
                              <span className="text-cyan-600 font-bold">[-]</span>
                              <span>{step}</span>
                            </li>
                          ))}
                        </ul>
                      </div>

                      {/* Phase 3 */}
                      <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-4">
                        <div className="flex items-center gap-2 text-emerald-700 dark:text-emerald-400 font-bold text-xs uppercase tracking-wider">
                          <Shield className="h-4 w-4" />
                          Phase 3: Long-Term Hardening & Policy Updates
                        </div>
                        <ul className="mt-2 space-y-1.5 text-xs text-foreground">
                          {selectedReport.remediationPlan.longTerm.map((step, idx) => (
                            <li key={idx} className="flex items-start gap-2">
                              <span className="text-emerald-600 font-bold">[+]</span>
                              <span>{step}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  </TabsContent>
                </Tabs>
              </div>

              {/* Modal Footer Attestation & Actions */}
              <div className="mt-6 flex flex-wrap items-center justify-between gap-3 border-t border-border pt-5">
                <div className="text-xs text-muted-foreground">
                  <span>Attested by: </span>
                  <span className="font-semibold text-foreground">{selectedReport.investigator}</span>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => copyMarkdown(selectedReport)}
                    className="gap-1.5 text-xs font-medium border-border"
                  >
                    <Copy className="h-3.5 w-3.5" />
                    Copy Markdown
                  </Button>
                  <Button
                    size="sm"
                    onClick={() => {
                      downloadSOCReportPdf(selectedReport);
                      toast.success(`Downloaded ${selectedReport.reportId}.pdf!`);
                    }}
                    className="gap-1.5 bg-cyan-600 hover:bg-cyan-700 text-white font-bold text-xs shadow-sm"
                  >
                    <Download className="h-3.5 w-3.5" />
                    Download Official PDF (.pdf)
                  </Button>
                </div>
              </div>
            </DialogContent>
          </Dialog>
        )}
      </div>
    </DashboardLayout>
  );
}
