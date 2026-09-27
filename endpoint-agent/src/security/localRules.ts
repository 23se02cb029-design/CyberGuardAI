type Signal = {
  eventType: string;
  sourceIp: string;
  destinationIp: string;
  protocol: string;
  port: number;
  process: string;
  bytesSent: number;
  bytesReceived: number;
  status: "suspicious" | "blocked" | "normal";
  confidence: number;
  flags: string[];
};

export function evaluateLocalSignals(network: any[], processes: any[]): Signal[] {
  const processNames = new Set((processes || []).map((p) => String(p.name || "").toLowerCase()));
  const suspiciousNames = ["mimikatz", "rundll32", "powershell", "cmd.exe", "nc.exe", "ncat", "nmap", "netcat"];

  return (network || [])
    .filter((entry) => {
      const remote = String(entry.remote || "");
      const local = String(entry.local || "");
      const suspiciousRemote = remote.includes(":") && !remote.startsWith("0.0.0.0") && !remote.startsWith("127.0.0.1");
      const suspiciousProcess = Array.from(processNames).some((name) => suspiciousNames.some((candidate) => name.includes(candidate)));
      return suspiciousRemote || suspiciousProcess;
    })
    .slice(0, 10)
    .map((entry) => {
      const process = (processes || [])[0]?.name || "unknown";
      return {
        eventType: "network-connection",
        sourceIp: "127.0.0.1",
        destinationIp: entry.remote.split(":")[0] || "unknown",
        protocol: entry.protocol || "TCP",
        port: Number((entry.remote.match(/:(\d+)$/)?.[1] || 0)),
        process,
        bytesSent: 128,
        bytesReceived: 64,
        status: "suspicious",
        confidence: 0.72,
        flags: ["external-connection", "metadata-only"],
      };
    });
}
