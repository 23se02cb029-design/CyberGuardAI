import { useState, useEffect } from "react";
import { useRoute, useLocation } from "wouter";
import DashboardLayout from "@/components/DashboardLayout";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { trpc } from "@/lib/trpc";
import {
  AlertTriangle,
  Shield,
  Clock,
  Target,
  Zap,
  FileText,
  CheckCircle2,
  AlertCircle,
  ArrowRight,
  Copy,
  Download,
  Trash2,
} from "lucide-react";
import { toast } from "sonner";

const threatIcons: Record<string, React.ReactNode> = {
  phishing: <AlertTriangle className="h-6 w-6 text-orange-500" />,
  brute_force: <Zap className="h-6 w-6 text-red-500" />,
  malware: <Shield className="h-6 w-6 text-purple-500" />,
  lateral_movement: <Target className="h-6 w-6 text-blue-500" />,
  data_exfiltration: <AlertTriangle className="h-6 w-6 text-red-600" />,
  privilege_escalation: <Zap className="h-6 w-6 text-orange-600" />,
  unknown: <Shield className="h-6 w-6 text-gray-500" />,
};

const getRiskLevel = (score: number | null) => {
  if (!score) return "low";
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 40) return "medium";
  return "low";
};

const severityColors: Record<string, string> = {
  critical: "bg-red-100 text-red-800 border-red-300",
  high: "bg-orange-100 text-orange-800 border-orange-300",
  medium: "bg-yellow-100 text-yellow-800 border-yellow-300",
  low: "bg-green-100 text-green-800 border-green-300",
};

export default function ThreatDetail() {
  const [, params] = useRoute("/threats/:id");
  const [, navigate] = useLocation();
  const [threat, setThreat] = useState<any>(null);
  const [recommendations, setRecommendations] = useState<any>(null);
  const [newStatus, setNewStatus] = useState<string>("");
  const [isUpdating, setIsUpdating] = useState(false);

  const threatId = params?.id ? parseInt(params.id) : 0;
  const threatQuery = trpc.threats.getById.useQuery({ id: threatId }, { enabled: threatId > 0 });
  const recommendationsQuery = trpc.recommendations.getByThreatId.useQuery(
    { threatDetectionId: threatId },
    { enabled: threatId > 0 }
  );

  const updateStatusMutation = trpc.threats.updateStatus.useMutation({
    onSuccess: () => {
      toast.success("Threat status updated");
      setIsUpdating(false);
      threatQuery.refetch();
    },
    onError: (error) => {
      toast.error(`Failed to update status: ${error.message}`);
      setIsUpdating(false);
    },
  });

  const generateReportMutation = trpc.reports.generate.useMutation({
    onSuccess: () => {
      toast.success("Report generated successfully");
    },
    onError: (error) => {
      toast.error(`Failed to generate report: ${error.message}`);
    },
  });
  const trpcUtils = trpc.useUtils();
  const removeThreatMutation = trpc.threats.remove.useMutation({
    onSuccess: () => {
      toast.success("Threat removed");
      void trpcUtils.threats.list.invalidate();
      void trpcUtils.dashboard.metrics.invalidate();
      navigate("/threats");
    },
    onError: (error) => toast.error(`Failed to remove threat: ${error.message}`),
  });

  useEffect(() => {
    if (threatQuery.data) {
      setThreat(threatQuery.data);
      setNewStatus(threatQuery.data.status || "new");
    }
  }, [threatQuery.data]);

  useEffect(() => {
    if (recommendationsQuery.data) {
      setRecommendations(recommendationsQuery.data);
    }
  }, [recommendationsQuery.data]);

  if (!threat) {
    return (
      <DashboardLayout>
        <div className="flex items-center justify-center h-96">
          <p className="text-muted-foreground">Loading threat details...</p>
        </div>
      </DashboardLayout>
    );
  }

  const riskLevel = getRiskLevel(threat.riskScore ? Number(threat.riskScore) : 0);
  const affectedAssets = threat.affectedAssets || {};
  const evidence = Array.isArray(threat.indicators) ? threat.indicators.filter((item: unknown): item is string => typeof item === "string") : [];
  const timeline: Array<{ event: string; timestamp?: string; sortValue: number }> = evidence
    .map((event: string) => {
      const timestamp = event.match(/\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}/)?.[0];
      return { event, timestamp, sortValue: timestamp ? Date.parse(timestamp.replace(" ", "T")) : Number.MAX_SAFE_INTEGER };
    })
    .sort((left: { sortValue: number }, right: { sortValue: number }) => left.sortValue - right.sortValue);

  const handleStatusUpdate = () => {
    if (newStatus !== threat.status) {
      setIsUpdating(true);
      updateStatusMutation.mutate({
        id: threat.id,
        status: newStatus as any,
      });
    }
  };

  const handleGenerateReport = () => {
    generateReportMutation.mutate({
      threatDetectionId: threat.id,
      organizationId: threat.organizationId || 1,
      reportType: "combined",
    });
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success("Copied to clipboard");
  };

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-start justify-between gap-4">
          <div className="space-y-2">
            <div className="flex items-center gap-3">
              {threatIcons[threat.threatType || "unknown"]}
              <h1 className="text-4xl font-black tracking-tighter capitalize">
                {threat.threatType?.replace(/_/g, " ") || "Unknown Threat"}
              </h1>
              <Badge className={`${severityColors[riskLevel]}`}>
                {riskLevel.toUpperCase()}
              </Badge>
            </div>
            <p className="tech-label">Threat ID: {threat.id}</p>
          </div>
          <div className="text-right">
            <div className="text-5xl font-black text-orange-600">
              {threat.riskScore ? Number(threat.riskScore).toFixed(1) : "0"}
            </div>
            <p className="text-xs text-muted-foreground">Risk Score</p>
          </div>
        </div>

        {/* Quick Actions */}
        <div className="flex flex-wrap gap-2">
          <Button onClick={handleGenerateReport} className="gap-2">
            <FileText className="h-4 w-4" />
            Generate Report
          </Button>
          <Button variant="outline" onClick={() => copyToClipboard(JSON.stringify(threat))}>
            <Copy className="h-4 w-4" />
            Copy Details
          </Button>
          <Button
            variant="outline"
            className="gap-2 text-red-600 hover:bg-red-50 hover:text-red-700"
            disabled={removeThreatMutation.isPending}
            onClick={() => {
              if (window.confirm("Remove this threat and its recommendations?")) {
                removeThreatMutation.mutate({ id: threat.id });
              }
            }}
          >
            <Trash2 className="h-4 w-4" />
            {removeThreatMutation.isPending ? "Removing..." : "Remove Threat"}
          </Button>
        </div>

        {/* Main Content Tabs */}
        <Tabs defaultValue="overview" className="space-y-4">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="assets">Affected Assets</TabsTrigger>
            <TabsTrigger value="remediation">Remediation</TabsTrigger>
            <TabsTrigger value="indicators">Indicators</TabsTrigger>
          </TabsList>

          {/* Overview Tab */}
          <TabsContent value="overview" className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Threat Analysis */}
              <Card className="blueprint-accent">
                <CardHeader>
                  <CardTitle className="text-lg">Threat Analysis</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div>
                    <p className="text-sm text-muted-foreground mb-1">Description</p>
                    <p className="text-sm">{threat.description || "No description available"}</p>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground mb-1">AI Analysis</p>
                    <p className="text-sm">{threat.aiAnalysis || "No detailed analysis available"}</p>
                  </div>
                  <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                    <div><p className="text-xs text-muted-foreground">Source IP</p><p className="text-sm">{affectedAssets.sourceIp || "Unavailable"}</p></div>
                    <div><p className="text-xs text-muted-foreground">Destination IP</p><p className="text-sm">{affectedAssets.destinationIp || "Unavailable"}</p></div>
                    <div><p className="text-xs text-muted-foreground">Timestamp</p><p className="text-sm">{affectedAssets.timestamp ? String(affectedAssets.timestamp) : new Date(threat.createdAt).toLocaleString()}</p></div>
                    <div><p className="text-xs text-muted-foreground">Confidence</p><p className="text-sm">{threat.confidence || 0}%</p></div>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground mb-1">Exact Evidence</p>
                    <pre className="whitespace-pre-wrap rounded border p-3 text-xs">{evidence.length ? evidence.join("\n") : "No evidence recorded"}</pre>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground mb-2">Related Event Timeline</p>
                    <div className="space-y-2 border-l-2 border-cyan-500/30 pl-4">
                      {timeline.length ? timeline.map((item: { event: string; timestamp?: string; sortValue: number }, index: number) => (
                        <div key={`${item.event}-${index}`} className="relative text-xs">
                          <span className="absolute -left-[21px] top-1 h-2 w-2 rounded-full bg-cyan-500" />
                          <p className="font-medium text-zinc-700 dark:text-zinc-300">{item.timestamp || "Timestamp unavailable"}</p>
                          <p className="text-muted-foreground">{item.event}</p>
                        </div>
                      )) : <p className="text-xs text-muted-foreground">No timestamped events recorded.</p>}
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <p className="text-xs text-muted-foreground">Confidence</p>
                      <p className="text-lg font-bold">{threat.confidence || 0}%</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">Detection Time</p>
                      <p className="text-sm">{new Date(threat.createdAt).toLocaleString()}</p>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Status Management */}
              <Card className="blueprint-accent">
                <CardHeader>
                  <CardTitle className="text-lg">Status Management</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div>
                    <label className="text-sm font-medium mb-2 block">Current Status</label>
                    <Select value={newStatus} onValueChange={setNewStatus}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="new">New</SelectItem>
                        <SelectItem value="investigating">Investigating</SelectItem>
                        <SelectItem value="confirmed">Confirmed</SelectItem>
                        <SelectItem value="false_positive">False Positive</SelectItem>
                        <SelectItem value="resolved">Resolved</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <Button
                    onClick={handleStatusUpdate}
                    disabled={isUpdating || newStatus === threat.status}
                    className="w-full"
                  >
                    {isUpdating ? "Updating..." : "Update Status"}
                  </Button>
                </CardContent>
              </Card>
            </div>

            {/* MITRE ATT&CK Mapping */}
            <Card className="blueprint-accent">
              <CardHeader>
                <CardTitle className="text-lg">MITRE ATT&CK Framework</CardTitle>
                <CardDescription>Mapped attack techniques and tactics</CardDescription>
              </CardHeader>
              <CardContent>
                {threat.mitreAttackIds && threat.mitreAttackIds.length > 0 ? (
                  <div className="flex flex-wrap gap-2">
                    {threat.mitreAttackIds.map((id: string) => (
                      <Badge key={id} variant="outline" className="cursor-pointer">
                        {id}
                      </Badge>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">No MITRE ATT&CK mappings available</p>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* Affected Assets Tab */}
          <TabsContent value="assets" className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Source Information */}
              <Card className="blueprint-accent">
                <CardHeader>
                  <CardTitle className="text-lg flex items-center gap-2">
                    <AlertCircle className="h-5 w-5" />
                    Source
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  {affectedAssets.sourceIp && (
                    <div>
                      <p className="text-xs text-muted-foreground mb-1">Source IP</p>
                      <div className="flex items-center justify-between">
                        <p className="font-mono text-sm">{affectedAssets.sourceIp}</p>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => copyToClipboard(affectedAssets.sourceIp)}
                        >
                          <Copy className="h-3 w-3" />
                        </Button>
                      </div>
                    </div>
                  )}
                  {affectedAssets.sourceHostname && (
                    <div>
                      <p className="text-xs text-muted-foreground mb-1">Source Hostname</p>
                      <p className="font-mono text-sm">{affectedAssets.sourceHostname}</p>
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* Destination Information */}
              <Card className="blueprint-accent">
                <CardHeader>
                  <CardTitle className="text-lg flex items-center gap-2">
                    <Target className="h-5 w-5" />
                    Destination
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  {affectedAssets.destinationIp && (
                    <div>
                      <p className="text-xs text-muted-foreground mb-1">Destination IP</p>
                      <div className="flex items-center justify-between">
                        <p className="font-mono text-sm">{affectedAssets.destinationIp}</p>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => copyToClipboard(affectedAssets.destinationIp)}
                        >
                          <Copy className="h-3 w-3" />
                        </Button>
                      </div>
                    </div>
                  )}
                  {affectedAssets.destinationHostname && (
                    <div>
                      <p className="text-xs text-muted-foreground mb-1">Destination Hostname</p>
                      <p className="font-mono text-sm">{affectedAssets.destinationHostname}</p>
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* User Information */}
              {affectedAssets.userId && (
                <Card className="blueprint-accent">
                  <CardHeader>
                    <CardTitle className="text-lg">Affected User</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div>
                      <p className="text-xs text-muted-foreground mb-1">User ID</p>
                      <div className="flex items-center justify-between">
                        <p className="font-mono text-sm">{affectedAssets.userId}</p>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => copyToClipboard(affectedAssets.userId)}
                        >
                          <Copy className="h-3 w-3" />
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Additional Assets */}
              {Object.keys(affectedAssets).length > 3 && (
                <Card className="blueprint-accent">
                  <CardHeader>
                    <CardTitle className="text-lg">Additional Assets</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    {Object.entries(affectedAssets).map(([key, value]) => {
                      if (!["sourceIp", "destinationIp", "userId", "sourceHostname", "destinationHostname"].includes(key)) {
                        return (
                          <div key={key}>
                            <p className="text-xs text-muted-foreground capitalize">{key}</p>
                            <p className="text-sm font-mono">{String(value)}</p>
                          </div>
                        );
                      }
                    })}
                  </CardContent>
                </Card>
              )}
            </div>
          </TabsContent>

          {/* Remediation Tab */}
          <TabsContent value="remediation" className="space-y-4">
            {recommendations ? (
              <>
                {/* Priority Badge */}
                <Card className="blueprint-accent border-orange-300">
                  <CardHeader>
                    <CardTitle className="text-lg">Priority Level</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <Badge className={`${severityColors[recommendations.priority]}`}>
                      {recommendations.priority?.toUpperCase()}
                    </Badge>
                    <p className="text-sm text-muted-foreground mt-2">{recommendations.aiGeneratedText}</p>
                  </CardContent>
                </Card>

                {/* Short-term Actions */}
                <Card className="blueprint-accent">
                  <CardHeader>
                    <CardTitle className="text-lg flex items-center gap-2">
                      <Clock className="h-5 w-5" />
                      Immediate Actions (0-24 hours)
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    {recommendations.shortTermActions?.map((action: any, idx: number) => (
                      <div key={idx} className="border-l-2 border-orange-400 pl-4 py-2">
                        <div className="flex items-start justify-between gap-2 mb-1">
                          <h4 className="font-semibold text-sm">{action.description}</h4>
                          <Badge variant="outline" className="text-xs">
                            {action.complexity}
                          </Badge>
                        </div>
                        <div className="flex items-center gap-4 text-xs text-muted-foreground">
                          <span>⏱️ {action.estimatedHours}h</span>
                          <span>👥 {action.responsibleTeam}</span>
                        </div>
                      </div>
                    ))}
                  </CardContent>
                </Card>

                {/* Long-term Actions */}
                <Card className="blueprint-accent">
                  <CardHeader>
                    <CardTitle className="text-lg flex items-center gap-2">
                      <Zap className="h-5 w-5" />
                      Strategic Actions (1-30 days)
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    {recommendations.longTermActions?.map((action: any, idx: number) => (
                      <div key={idx} className="border-l-2 border-blue-400 pl-4 py-2">
                        <div className="flex items-start justify-between gap-2 mb-1">
                          <h4 className="font-semibold text-sm">{action.description}</h4>
                          <Badge variant="outline" className="text-xs">
                            {action.complexity}
                          </Badge>
                        </div>
                        <div className="flex items-center gap-4 text-xs text-muted-foreground">
                          <span>⏱️ {action.estimatedHours}h</span>
                          <span>👥 {action.responsibleTeam}</span>
                        </div>
                      </div>
                    ))}
                  </CardContent>
                </Card>
              </>
            ) : (
              <Card>
                <CardContent className="py-8 text-center">
                  <p className="text-muted-foreground">No remediation recommendations available</p>
                </CardContent>
              </Card>
            )}
          </TabsContent>

          {/* Indicators Tab */}
          <TabsContent value="indicators" className="space-y-4">
            <Card className="blueprint-accent">
              <CardHeader>
                <CardTitle className="text-lg">Indicators of Compromise (IOCs)</CardTitle>
                <CardDescription>Artifacts and patterns associated with this threat</CardDescription>
              </CardHeader>
              <CardContent>
                {threat.indicators && threat.indicators.length > 0 ? (
                  <div className="space-y-2">
                    {threat.indicators.map((indicator: string, idx: number) => (
                      <div
                        key={idx}
                        className="flex items-center justify-between p-3 bg-gray-50 rounded-lg border border-gray-200"
                      >
                        <div className="flex items-center gap-2">
                          <CheckCircle2 className="h-4 w-4 text-green-600" />
                          <p className="text-sm font-mono">{indicator}</p>
                        </div>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => copyToClipboard(indicator)}
                        >
                          <Copy className="h-3 w-3" />
                        </Button>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">No indicators available</p>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>

        {/* Related Information */}
        <Card className="blueprint-accent">
          <CardHeader>
            <CardTitle className="text-lg">Related Information</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div>
                <p className="text-xs text-muted-foreground">Detection Time</p>
                <p className="text-sm font-semibold">{new Date(threat.createdAt).toLocaleString()}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Source Type</p>
                <p className="text-sm font-semibold capitalize">{threat.sourceType || "Unknown"}</p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Status</p>
                <Badge className="mt-1">{threat.status?.toUpperCase()}</Badge>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Confidence</p>
                <p className="text-sm font-semibold">{threat.confidence || 0}%</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
}
