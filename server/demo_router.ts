import { Router } from "express";
import crypto from "crypto";
import { exec } from "child_process";
import { promisify } from "util";
import { authenticateRequest } from "./_core/session";
import * as db from "./db";
import {
  deriveSeverityFromRiskScore,
  getMitreIdsForVulnerabilities,
  normalizeLogHeuristically,
  runSecurityAnalysis,
  type SecurityAnalysis,
} from "./services/securityEngine";

const router = Router();
const execAsync = promisify(exec);

async function persistCandidateDetections(
  organizationId: number,
  logId: number,
  analysis: SecurityAnalysis,
  logContext: { sourceIp?: string | null; destinationIp?: string | null; userId?: string | null; timestamp?: Date | null }
) {
  for (const candidate of analysis.detections) {
    if (await db.getThreatDetectionByLogAndType(organizationId, logId, candidate.threatType)) continue;

    const threat = await db.createThreatDetection({
      organizationId,
      logId,
      threatType: candidate.threatType,
      riskScore: String(candidate.riskScore),
      confidence: String(candidate.confidence),
      mitreAttackIds: getMitreIdsForVulnerabilities([candidate.reasoning]),
      indicators: candidate.evidence,
      affectedAssets: {
        sourceIp: candidate.sourceIp || logContext.sourceIp,
        destinationIp: candidate.destinationIp || logContext.destinationIp,
        userId: logContext.userId,
        timestamp: candidate.timestamp || logContext.timestamp,
        severity: candidate.severity,
        evidence: candidate.evidence,
      },
      description: candidate.reasoning,
      aiAnalysis: `${candidate.reasoning} Evidence: ${candidate.evidence.join(" | ")}`,
      status: "new",
    });

    await db.createIncidentRecommendation({
      threatDetectionId: threat.id,
      organizationId,
      shortTermActions: [{
        description: candidate.recommendedAction,
        estimatedHours: 1,
        complexity: "medium",
        responsibleTeam: "SOC",
      }],
      longTermActions: [{
        description: "Audit the broader environment for the same evidence-backed detection and add regression coverage.",
        estimatedHours: 8,
        complexity: "medium",
        responsibleTeam: "Security",
      }],
      priority: candidate.riskScore >= 80 ? "critical" : candidate.riskScore >= 60 ? "high" : candidate.riskScore >= 40 ? "medium" : "low",
      aiGeneratedText: candidate.reasoning,
      status: "pending",
    });

    console.info(`[DEMO_THREAT_DB_INSERT_SUCCESS] id=${threat.id} logId=${logId} type=${candidate.threatType}`);
  }
}

async function captureNetworkSnapshot(): Promise<string> {
  try {
    if (process.platform === "win32") {
      const { stdout } = await execAsync("netstat -ano");
      return stdout;
    }

    try {
      const { stdout } = await execAsync("ss -tunap");
      return stdout;
    } catch {
      const { stdout } = await execAsync("netstat -an");
      return stdout;
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return `Live network capture unavailable on this environment. Details: ${message}`;
  }
}

const KNOWN_SERVICES: Record<string, string> = {
  "22": "SSH",
  "53": "DNS",
  "80": "HTTP",
  "443": "HTTPS",
  "445": "SMB",
  "3389": "RDP",
  "4444": "C2_BEACON",
  "8080": "HTTP-ALT",
  "8443": "HTTPS-ALT",
};

const SUSPICIOUS_PORTS = new Set(["4444", "1337", "6667", "31337", "8888", "4445"]);

function parseNetworkConnections(snapshot: string) {
  return snapshot.split(/\r?\n/).flatMap((line) => {
    const match = line.match(/^\s*(TCP|UDP)\s+([^\s]+)\s+([^\s]+)(?:\s+(LISTENING|ESTABLISHED|TIME_WAIT|CLOSE_WAIT))?/i);
    if (!match) return [];
    const splitEndpoint = (endpoint: string) => {
      const separator = endpoint.lastIndexOf(":");
      return separator > -1 ? { ip: endpoint.slice(0, separator), port: endpoint.slice(separator + 1) } : { ip: endpoint, port: "" };
    };
    const source = splitEndpoint(match[2]);
    const destination = splitEndpoint(match[3]);
    const destPort = destination.port;
    const isSuspicious = SUSPICIOUS_PORTS.has(destPort);
    const service = KNOWN_SERVICES[destPort] || (destPort ? `PORT-${destPort}` : "UNKNOWN");

    return [{
      timestamp: new Date().toISOString(),
      sourceIp: source.ip || "127.0.0.1",
      destinationIp: destination.ip || "0.0.0.0",
      sourcePort: source.port || "-",
      destinationPort: destination.port || "-",
      protocol: match[1].toUpperCase(),
      service,
      action: isSuspicious ? "BLOCK" : "ALLOW",
      severity: isSuspicious ? "high" : "low",
      threatStatus: isSuspicious ? "suspicious" : "normal",
      state: match[4] || "ESTABLISHED",
      processName: isSuspicious ? "powershell.exe" : "svchost.exe",
    }];
  });
}

/**
 * Adapts the shared { riskScore, vulnerabilities, reasoning, remediationSteps }
 * schema into the legacy display shape DemoPage.tsx already renders
 * (threat_type / storytelling / recommendation), so the frontend needed no
 * rewrite when the engine underneath changed.
 */
function adaptToLegacyShape(analysis: SecurityAnalysis) {
  return {
    threat_type: analysis.vulnerabilities[0] || "No Significant Threat",
    risk_score: analysis.riskScore,
    reasoning: analysis.reasoning,
    storytelling: {
      why_dangerous: analysis.vulnerabilities.join("; ") || "No specific vulnerabilities identified.",
      if_ignored:
        "Continued exposure increases the likelihood of successful compromise, lateral movement, or data loss.",
      mitigation: analysis.remediationSteps.join(" "),
    },
    recommendation: analysis.remediationSteps[0] || "Continue routine monitoring.",
  };
}

/**
 * ==========================================
 * INCIDENT REPORT GENERATOR
 * ==========================================
 */
function generateIncidentReport(analysis: ReturnType<typeof adaptToLegacyShape>, logData: string) {
  const timestamp = new Date().toISOString();
  const reportId = `CG-INC-${Math.floor(1000 + Math.random() * 9000)}`;

  return {
    report_metadata: {
      report_id: reportId,
      timestamp,
      status: analysis.risk_score > 50 ? "CRITICAL" : "STABLE",
    },
    executive_summary: {
      overview: `CyberGuard AI identified ${analysis.threat_type} with a risk score of ${analysis.risk_score}/100.`,
      impact_level:
        analysis.risk_score > 70
          ? "High - Potential System Compromise"
          : "Low - Routine Monitoring",
    },
    technical_details: {
      detected_threat: analysis.threat_type,
      raw_log_context:
        logData.substring(0, 200) + (logData.length > 200 ? "..." : ""),
      ai_reasoning: analysis.reasoning,
    },
    remediation_plan: {
      immediate_action: analysis.recommendation,
      long_term_strategy: analysis.storytelling.mitigation,
    }
  };
}

/**
 * ==========================================
 * API ENDPOINT: POST /api/live-network
 * ==========================================
 * Backs NetworkMonitor.tsx. Supports target selection:
 * - "local": Live local netstat capture
 * - "fleet": Aggregated enterprise telemetry across all PCs
 * - "endpoint": Workstation-specific telemetry for endpointId
 */
router.all("/live-network", async (req, res) => {
  try {
    let organizationId = 1;
    try {
      const user = await authenticateRequest(req);
      if (user?.organizationId) organizationId = user.organizationId;
    } catch {
      organizationId = 1;
    }

    const payload = req.method === "GET" ? req.query : (req.body || {});
    const { target = "fleet", endpointId } = payload as any;

    let snapshot = "";
    let connections: Array<any> = [];

    if ((target === "endpoint" && endpointId) || target === "fleet") {
      let telemetryRows: any[] = [];
      if (target === "endpoint" && endpointId) {
        telemetryRows = await db.getRecentTelemetryByEndpoint(Number(endpointId), 60);
      } else {
        telemetryRows = await db.getAllRecentTelemetry(organizationId, 100);
      }

      if (telemetryRows.length > 0) {
        connections = telemetryRows.map((row) => {
          const evtData = (row.eventData as Record<string, any>) || {};
          const destPort = String(evtData.destinationPort || "443");
          const isSuspicious = Number(row.riskScore) >= 60 || SUSPICIOUS_PORTS.has(destPort) || (evtData.flags && evtData.flags.includes("suspicious"));
          return {
            timestamp: row.createdAt ? new Date(row.createdAt).toISOString() : new Date().toISOString(),
            sourceIp: row.sourceIp || "192.168.1.45",
            destinationIp: row.destinationIp || "142.250.190.46",
            sourcePort: String(evtData.sourcePort || 51234),
            destinationPort: destPort,
            protocol: (row.protocol || "TCP").toUpperCase(),
            service: KNOWN_SERVICES[destPort] || `PORT-${destPort}`,
            action: isSuspicious ? "BLOCK" : "ALLOW",
            severity: row.severity || (isSuspicious ? "high" : "low"),
            threatStatus: isSuspicious ? "suspicious" : "normal",
            state: "ESTABLISHED",
            processName: row.processName || evtData.process || "system",
            hostname: evtData.hostname || "WORKSTATION",
          };
        });

        snapshot = telemetryRows.map((r) => `${r.createdAt?.toISOString()} [${r.eventType}] Host=${r.eventData?.hostname || "PC"} Src=${r.sourceIp} Dest=${r.destinationIp}:${r.eventData?.destinationPort} Proc=${r.processName} Risk=${r.riskScore}`).join("\n");
      }
    }

    if (connections.length === 0) {
      snapshot = await captureNetworkSnapshot();
      connections = parseNetworkConnections(snapshot);
    }

    const { source, ...analysis } = await runSecurityAnalysis(snapshot);

    try {
      const normalized = normalizeLogHeuristically(snapshot, "live_network");
      const logHash = crypto.createHash("sha256").update(snapshot).digest("hex");
      const log =
        (await db.createSecurityLog({
          organizationId,
          sourceType: "other",
          rawLog: snapshot,
          normalizedLog: normalized,
          timestamp: normalized.timestamp ? new Date(normalized.timestamp) : new Date(),
          sourceIp: normalized.sourceIp,
          destinationIp: normalized.destinationIp,
          userId: normalized.userId,
          eventType: normalized.eventType,
          severity: normalized.severity || deriveSeverityFromRiskScore(analysis.riskScore),
          logHash,
        })) || (await db.getSecurityLogByHash(logHash));

      if (log) {
        await persistCandidateDetections(organizationId, log.id, analysis, log);
      }
    } catch (persistErr) {
      // Non-fatal if telemetry persistence cannot record
      console.warn("[LIVE_NETWORK] Telemetry logging skipped:", persistErr);
    }

    const protocolCounts: Record<string, number> = {};
    for (const c of connections) {
      const p = c.protocol || "TCP";
      protocolCounts[p] = (protocolCounts[p] || 0) + 1;
    }

    const result = {
      status: analysis.vulnerabilities.length || connections.some((c) => c.threatStatus !== "normal") ? "alert" : "normal",
      alert: analysis.vulnerabilities.length > 0 || connections.some((c) => c.threatStatus !== "normal"),
      riskScore: Math.max(analysis.riskScore, connections.some((c) => c.threatStatus !== "normal") ? 72 : 12),
      vulnerabilities: analysis.vulnerabilities,
      reasoning: analysis.reasoning,
      remediationSteps: analysis.remediationSteps,
      source,
      snapshotPreview: snapshot.slice(0, 1500),
      connections,
      target,
      connectionStats: {
        totalConnections: connections.length,
        allowed: connections.filter((c) => c.action === "ALLOW").length,
        blocked: connections.filter((c) => c.action === "BLOCK").length,
        suspicious: connections.filter((c) => c.threatStatus !== "normal").length,
        threats: Math.max(analysis.detections.length, connections.filter((c) => c.threatStatus !== "normal").length),
      },
      protocols: protocolCounts,
    };

    return res.json(result);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[LIVE_NETWORK_ANALYSIS_FAILED] ${message}`);
    return res.status(500).json({ error: message });
  }
});

router.post("/analyze", async (req, res) => {
  try {
    const { logData } = req.body;

    if (!logData || typeof logData !== "string") {
      return res.status(400).json({ error: "No log data provided" });
    }

    let organizationId = 1;
    try {
      const user = await authenticateRequest(req);
      if (user?.organizationId) organizationId = user.organizationId;
    } catch {
      organizationId = 1;
    }

    const { source, ...analysis } = await runSecurityAnalysis(logData);
    const normalized = normalizeLogHeuristically(logData, "demo");
    const logHash = crypto.createHash("sha256").update(logData).digest("hex");
    const log =
    (await db.createSecurityLog({
      organizationId,
      sourceType: "other",
      rawLog: logData,
      normalizedLog: normalized,
      timestamp: normalized.timestamp ? new Date(normalized.timestamp) : new Date(),
      sourceIp: normalized.sourceIp,
      destinationIp: normalized.destinationIp,
      userId: normalized.userId,
      eventType: normalized.eventType,
      severity: normalized.severity || deriveSeverityFromRiskScore(analysis.riskScore),
      logHash,
    })) || (await db.getSecurityLogByHash(logHash));

    if (!log) return res.status(500).json({ error: "Failed to persist analyzed log" });

    await persistCandidateDetections(organizationId, log.id, analysis, log);

    const adapted = adaptToLegacyShape(analysis);
    const report = generateIncidentReport(adapted, logData);

    return res.json({
      ...adapted,
      report,
      source,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[DEMO_ANALYSIS_FAILED] ${message}`);
    return res.status(500).json({ error: message });
  }
});

export default router;
