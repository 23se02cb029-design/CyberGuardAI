import { useRef, useState } from "react";
import DashboardLayout from "@/components/DashboardLayout";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { trpc } from "@/lib/trpc";
import { useAuth } from "@/_core/hooks/useAuth";
import { Upload, FileText, AlertCircle, ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import { useLocation } from "wouter";

const MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024; // 2MB per upload
const PREVIEW_LINE_COUNT = 8;

export default function LogUpload() {
  const [, navigate] = useLocation();
  const { user } = useAuth();
  const organizationId = user?.organizationId ?? 1;
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [dragActive, setDragActive] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [previewLines, setPreviewLines] = useState<string[]>([]);
  const [lineCount, setLineCount] = useState(0);
  const [sourceType, setSourceType] = useState<string>("firewall");
  const [threatsDetected, setThreatsDetected] = useState<number | null>(null);
  const trpcUtils = trpc.useUtils();

  const analyzeMutation = trpc.threats.analyze.useMutation({
    onSuccess: (data) => {
      if (data.success) {
        setThreatsDetected(data.threatsDetected);
        void trpcUtils.threats.list.invalidate();
        void trpcUtils.dashboard.metrics.invalidate();
        toast.success(`Analysis complete — ${data.threatsDetected} threat(s) detected`);
      } else {
        toast.error(data.message);
      }
    },
    onError: (error) => {
      toast.error(`Threat analysis failed: ${error.message}`);
    },
  });

  const uploadMutation = trpc.logs.upload.useMutation({
    onSuccess: (data) => {
      const duplicateNote = data.duplicatesSkipped > 0 ? ` (${data.duplicatesSkipped} duplicate line(s) skipped)` : "";
      toast.success(`Successfully uploaded ${data.logsCreated} logs${duplicateNote} — running threat analysis...`);
      setFile(null);
      setPreviewLines([]);
      setLineCount(0);
      // Immediately run the log/threat pipeline so Threats.tsx and the
      // Dashboard metrics reflect this upload without a separate manual step.
      analyzeMutation.mutate({ organizationId });
    },
    onError: (error) => {
      toast.error(`Upload failed: ${error.message}`);
    },
  });

  const isBusy = uploadMutation.isPending || analyzeMutation.isPending;

  const loadFile = async (selected: File) => {
    if (selected.size > MAX_FILE_SIZE_BYTES) {
      toast.error(`File too large — max ${(MAX_FILE_SIZE_BYTES / (1024 * 1024)).toFixed(0)}MB per upload`);
      return;
    }

    setThreatsDetected(null);
    setFile(selected);

    const content = await selected.text();
    const lines = content.split("\n").filter(Boolean);
    setLineCount(lines.length);
    setPreviewLines(lines.slice(0, PREVIEW_LINE_COUNT));
  };

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      loadFile(e.dataTransfer.files[0]);
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      loadFile(e.target.files[0]);
    }
  };

  const handleRemoveFile = () => {
    setFile(null);
    setPreviewLines([]);
    setLineCount(0);
  };

  const handleUpload = async () => {
    if (!file) {
      toast.error("Please select a file");
      return;
    }

    const content = await file.text();

    uploadMutation.mutate({
      sourceType: sourceType as any,
      logData: content,
      fileName: file.name,
    });
  };

  return (
    <DashboardLayout>
      <div className="min-h-[calc(100vh-2rem)] space-y-8 bg-background p-5 text-foreground sm:p-7">
        <div className="space-y-2">
          <p className="tech-label text-cyan-300">CyberGuard AI // Ingestion</p>
          <h1 className="text-4xl font-black tracking-tight text-slate-900 sm:text-5xl dark:text-white">Upload Security Logs</h1>
          <p className="text-sm text-muted-foreground">Drop evidence into the analysis pipeline. CSV, JSON, syslog, and plain text supported.</p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Upload Area */}
          <div className="lg:col-span-2">
            <Card className="soc-surface border-0">
              <CardHeader>
                <CardTitle>Select Log File</CardTitle>
                <CardDescription>Drag and drop or click to browse</CardDescription>
              </CardHeader>
              <CardContent>
                <div
                  className={`cursor-pointer rounded-xl border-2 border-dashed p-12 text-center transition-colors ${
                    dragActive ? "border-cyan-300 bg-cyan-400/10" : "border-slate-700 hover:border-cyan-400/60"
                  }`}
                  onDragEnter={handleDrag}
                  onDragLeave={handleDrag}
                  onDragOver={handleDrag}
                  onDrop={handleDrop}
                  onClick={() => fileInputRef.current?.click()}
                >
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".csv,.json,.log,.txt"
                    onChange={handleChange}
                    className="hidden"
                  />
                  <Upload className="mx-auto mb-4 h-12 w-12 text-cyan-300" />
                  <p className="mb-2 text-lg font-semibold text-white">Drop security logs here</p>
                  <p className="mb-4 text-sm text-slate-500">or</p>
                  <Button
                    variant="outline"
                    onClick={(e) => {
                      e.stopPropagation();
                      fileInputRef.current?.click();
                    }}
                  >
                    Browse Files
                  </Button>
                </div>

                {file && (
                  <>
                    <div className="mt-6 flex items-center gap-3 rounded-lg border border-cyan-400/20 bg-cyan-400/5 p-4">
                      <FileText className="h-5 w-5 text-cyan-300" />
                      <div className="flex-1">
                        <p className="font-semibold text-sm">{file.name}</p>
                        <p className="text-xs text-slate-400">
                          {(file.size / 1024).toFixed(2)} KB • {lineCount} line{lineCount === 1 ? "" : "s"}
                        </p>
                      </div>
                      <Button variant="ghost" size="sm" onClick={handleRemoveFile} disabled={isBusy}>
                        Remove
                      </Button>
                    </div>

                    {previewLines.length > 0 && (
                      <div className="mt-3 rounded-lg border border-slate-700 bg-slate-950/70 p-3">
                        <p className="mb-2 text-xs font-medium text-slate-500">
                          Preview — first {previewLines.length} of {lineCount} line{lineCount === 1 ? "" : "s"}
                        </p>
                        <pre className="max-h-48 overflow-y-auto whitespace-pre-wrap break-all font-mono text-xs text-cyan-100/80">
                          {previewLines.join("\n")}
                        </pre>
                      </div>
                    )}
                  </>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Configuration */}
          <div className="space-y-4">
            <Card className="soc-surface border-0">
              <CardHeader>
                <CardTitle className="text-lg">Log Source</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <label className="text-sm font-medium mb-2 block">Source Type</label>
                  <Select value={sourceType} onValueChange={setSourceType}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="firewall">Firewall</SelectItem>
                      <SelectItem value="ids">IDS/IPS</SelectItem>
                      <SelectItem value="auth_server">Auth Server</SelectItem>
                      <SelectItem value="endpoint">Endpoint</SelectItem>
                      <SelectItem value="siem">SIEM</SelectItem>
                      <SelectItem value="other">Other</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <Button
                  onClick={handleUpload}
                  disabled={!file || isBusy}
                  className="w-full"
                >
                  {uploadMutation.isPending
                    ? "Uploading..."
                    : analyzeMutation.isPending
                      ? "Analyzing threats..."
                      : "Upload & Analyze"}
                </Button>
              </CardContent>
            </Card>

            {threatsDetected !== null && (
              <Card className="blueprint-accent border-emerald-300">
                <CardContent className="flex items-center gap-3 py-4">
                  <ShieldCheck className="h-8 w-8 shrink-0 text-emerald-600" />
                  <div className="flex-1">
                    <p className="text-sm font-semibold">
                      {threatsDetected} threat{threatsDetected === 1 ? "" : "s"} detected
                    </p>
                    <p className="text-xs text-muted-foreground">Dashboard and Threats page updated</p>
                  </div>
                  <Button variant="outline" size="sm" onClick={() => navigate("/threats")}>
                    View
                  </Button>
                </CardContent>
              </Card>
            )}

            {/* Info Box */}
            <Card>
              <CardHeader>
                <CardTitle className="text-sm flex items-center gap-2">
                  <AlertCircle className="h-4 w-4" />
                  Supported Formats
                </CardTitle>
              </CardHeader>
              <CardContent className="text-sm space-y-2">
                <p>• CSV with headers</p>
                <p>• JSON arrays</p>
                <p>• Syslog format</p>
                <p>• Plain text logs</p>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}
