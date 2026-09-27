import crypto from "crypto";
import { generateJson } from "../gemini";

export interface SecurityAnalysis {
  riskScore: number;
  vulnerabilities: string[];
  reasoning: string;
  remediationSteps: string[];
  detections: DetectionCandidate[];
}

export interface DetectionCandidate {
  threatType: ThreatType;
  riskScore: number;
  confidence: number;
  severity: Severity;
  evidence: string[];
  reasoning: string;
  recommendedAction: string;
  sourceIp?: string;
  destinationIp?: string;
  timestamp?: string;
}

export type AnalysisSource = "gemini" | "heuristics";

export type ThreatType =
  | "phishing"
  | "brute_force"
  | "sql_injection"
  | "path_traversal"
  | "sensitive_file_access"
  | "malware"
  | "lateral_movement"
  | "data_exfiltration"
  | "privilege_escalation"
  | "unknown";

export type Severity = "low" | "medium" | "high" | "critical";

/* =========================
   Pattern libraries
========================= */

const SQLI_PATTERNS: RegExp[] = [
  /union\s+(all\s+)?select/i,
  /\bor\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?/i, // OR 1=1
  /'\s*or\s*'[^']*'\s*=\s*'[^']*'/i, // ' or 'x'='x'
  /;\s*drop\s+table/i,
  /drop\s+table/i,
  /insert\s+into\s+\w+\s*\(/i,
  /xp_cmdshell/i,
  /waitfor\s+delay/i,
  /exec(?:ute)?\s*\(\s*(sp|xp)_/i,
  /--\s*$/m, // trailing SQL comment terminator
];

const XSS_PATTERNS: RegExp[] = [
  /<script[\s>]/i,
  /<\/script>/i,
  /on(error|load|click|mouseover|focus|change)\s*=\s*['"]/i,
  /javascript:\s*\S+/i,
  /<img[^>]+onerror/i,
  /<iframe[\s>]/i,
  /document\.cookie/i,
];

const PATH_TRAVERSAL_PATTERNS: RegExp[] = [
  /\.\.\//,
  /\.\.\\/,
  /\.\.%2f/i,
  /\.\.%5c/i,
  /%2e%2e(%2f|\/)/i,
  /%252e%252e(%252f|\/)/i,
];

const MALWARE_EXEC_PATTERNS: RegExp[] = [
  /powershell(?:\.exe)?\s+.*(?:-enc|-encodedcommand|-w\s+hidden|-nop)/i,
  /<\?php\s+.*(?:system|exec|passthru|shell_exec|eval)\s*\(/i,
  /(?:meterpreter|reverse_tcp|c2_beacon|\/bin\/(?:ba)?sh\s+-i|nc\s+-e)/i,
  /whoami\s*;\s*id\b/i,
];

const PORT_SCAN_PATTERNS: RegExp[] = [
  /(?:port\s+scan|syn\s+scan|nmap\s+scan)/i,
  /ports?\s+(?:\d+,\s*){3,}/i,
  /SYN\s+flood|flood\s+from.*SYN/i,
];

const DOS_PATTERNS: RegExp[] = [
  /SYN[_-]FLOOD/i,
  /(?:tcp|udp|http)\s+flood/i,
  /(?:denial\s+of\s+service|ddos\s+attack)/i,
];

const SENSITIVE_FILE_PATTERNS: RegExp[] = [
  /(?:^|[\s="'])\/etc\/(?:passwd|shadow|sudoers)(?:$|[\s"'])/i,
  /(?:ssh_config|sshd_config|authorized_keys)/i,
  /(?:^|[\s="'])(?:sam|system)\.hive(?:$|[\s"'])/i,
];

const SUSPICIOUS_ACTIVITY_PATTERNS: RegExp[] = [
  /(?:unusual|anomalous|suspicious)\s+(?:network|connection|outbound|inbound|beaconing|activity)/i,
  /beaconing/i,
  /(?:repeated|intermittent)\s+(?:data|transfer|connections?)/i,
  /new\s+external\s+host/i,
  /unknown\s+external\s+host/i,
  /suspicious\s+outbound\s+connection/i,
  /(?:abnormal|unexpected)\s+(?:traffic|data\s+transfer|network\s+behavior)/i,
];

const AUTH_FAILURE_RE =
  /(failed password|authentication failure|invalid user|failed login|login failed|login_failed|status[=:]\s*failed|access denied)/i;
const IP_RE = /\d{1,3}(?:\.\d{1,3}){3}/;
const BRUTE_FORCE_THRESHOLD = 3;

/* =========================
   Individual detectors
========================= */

interface HeuristicMatch {
  vulnerability: string;
  weight: number;
  remediation: string;
  threatType: ThreatType;
  evidence: string[];
  confidence: number;
}

function linesWithMatch(text: string, patterns: RegExp[]): string[] {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && patterns.some((pattern) => pattern.test(line)));
}

function extractField(text: string, field: string): string | undefined {
  const match = text.match(new RegExp(`${field}[=:]\\s*["']?([^\s"']+)`, "i"));
  return match?.[1];
}

function extractContext(text: string): Pick<DetectionCandidate, "sourceIp" | "destinationIp" | "timestamp"> {
  const ips = text.match(new RegExp(IP_RE, "g")) || [];
  const timestamp = text.match(/\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?/)?.[0];
  return {
    sourceIp: extractField(text, "SourceIP") || ips[0],
    destinationIp: extractField(text, "DestinationIP") || ips[1],
    timestamp,
  };
}

function detectSqlInjection(text: string): HeuristicMatch | null {
  if (!SQLI_PATTERNS.some((pattern) => pattern.test(text))) return null;
  return {
    vulnerability: "SQL Injection — union/boolean/comment-based query manipulation detected",
    weight: 45,
    threatType: "sql_injection",
    evidence: linesWithMatch(text, SQLI_PATTERNS),
    confidence: 94,
    remediation:
      "Use parameterized queries or an ORM with bound parameters; never concatenate raw user input into SQL statements.",
  };
}

function detectXss(text: string): HeuristicMatch | null {
  if (!XSS_PATTERNS.some((pattern) => pattern.test(text))) return null;
  return {
    vulnerability: "Cross-Site Scripting (XSS) — injected script tag or event-handler payload detected",
    weight: 40,
    threatType: "malware",
    evidence: linesWithMatch(text, XSS_PATTERNS),
    confidence: 92,
    remediation:
      "Sanitize and HTML-encode all user-supplied output, and enforce a strict Content-Security-Policy to block inline script execution.",
  };
}

function detectPathTraversal(text: string): HeuristicMatch | null {
  if (!PATH_TRAVERSAL_PATTERNS.some((pattern) => pattern.test(text))) return null;
  return {
    vulnerability: "Path Traversal — directory-jump sequence targeting filesystem paths outside the web root",
    weight: 35,
    threatType: "path_traversal",
    evidence: linesWithMatch(text, PATH_TRAVERSAL_PATTERNS),
    confidence: 98,
    remediation:
      "Reject requests containing '../' sequences, resolve and canonicalize file paths server-side, and sandbox file access to an allow-listed directory.",
  };
}

function detectSensitiveFileAccess(text: string): HeuristicMatch | null {
  const evidence = linesWithMatch(text, SENSITIVE_FILE_PATTERNS);
  if (!evidence.length) return null;
  const denied = evidence.some((line) => /(?:status|action)[=:]\s*(?:denied|blocked)/i.test(line));
  return {
    vulnerability: "Sensitive File Access — sensitive filesystem configuration or credential file access was attempted",
    weight: denied ? 30 : 40,
    threatType: "sensitive_file_access",
    evidence,
    confidence: 97,
    remediation: denied
      ? "Review the denied request and confirm the account and source are authorized; continue monitoring for repeated attempts."
      : "Verify whether the access was authorized, review the account activity, and rotate exposed credentials if access was not expected.",
  };
}

function detectBruteForce(text: string): HeuristicMatch | null {
  const lines = text.split("\n");
  const attemptsBySource = new Map<string, number>();
  let totalFailures = 0;
  const evidenceBySource = new Map<string, string[]>();
  const successfulBySource = new Set<string>();

  for (const line of lines) {
    if (!/(?:auth|login|password|authentication)/i.test(line) || !AUTH_FAILURE_RE.test(line)) continue;
    totalFailures++;
    const ipMatch = line.match(IP_RE);
    const key = ipMatch ? ipMatch[0] : "unattributed source";
    attemptsBySource.set(key, (attemptsBySource.get(key) || 0) + 1);
    evidenceBySource.set(key, [...(evidenceBySource.get(key) || []), line.trim()]);
  }

  for (const line of lines) {
    if (!/(?:login|authentication)/i.test(line) || !/(?:success|accepted|logged in)/i.test(line)) continue;
    const ipMatch = line.match(IP_RE);
    if (ipMatch) successfulBySource.add(ipMatch[0]);
  }

  if (totalFailures === 0) return null;

  const [topSource, topCount] = Array.from(attemptsBySource.entries()).sort((a, b) => b[1] - a[1])[0];

  if (topCount < BRUTE_FORCE_THRESHOLD) {
    return {
      vulnerability: `Authentication Failures — ${totalFailures} failed login attempt(s) observed`,
      weight: 15,
      threatType: "brute_force",
      evidence: evidenceBySource.get(topSource) || [],
      confidence: 88,
      remediation: "Monitor for repeated failures from the same source and enforce account lockout thresholds.",
    };
  }

  const followedBySuccess = successfulBySource.has(topSource);
  const weight = Math.min(70, (followedBySuccess ? 55 : 35) + (topCount - BRUTE_FORCE_THRESHOLD) * 5);
  return {
    vulnerability: `${followedBySuccess ? "Possible Brute-Force / Credential Attack" : "Repeated Authentication Failures"} — ${topCount} failed authentication attempts from ${topSource}${followedBySuccess ? " followed by a successful login" : ""}`,
    weight,
    threatType: "brute_force",
    evidence: [...(evidenceBySource.get(topSource) || []), ...lines.filter((line) => line.includes(topSource) && /(?:success|accepted|logged in)/i.test(line))],
    confidence: followedBySuccess ? 91 : 86,
    remediation: `Block ${topSource} at the firewall, enforce account lockout after ${BRUTE_FORCE_THRESHOLD} failures, and require MFA on the targeted account.`,
  };
}

function detectSuspiciousActivity(text: string): HeuristicMatch | null {
  if (!SUSPICIOUS_ACTIVITY_PATTERNS.some((pattern) => pattern.test(text))) return null;

  return {
    vulnerability: "Suspicious Activity — unusual beaconing, repeated outbound connections, or anomalous network behavior was detected",
    weight: 25,
    threatType: "unknown",
    evidence: linesWithMatch(text, SUSPICIOUS_ACTIVITY_PATTERNS),
    confidence: 78,
    remediation:
      "Investigate the source and destination endpoints, verify whether the traffic is expected, and block or isolate the suspicious host if it is unauthorized.",
  };
}

function detectMalwareExecution(text: string): HeuristicMatch | null {
  if (!MALWARE_EXEC_PATTERNS.some((p) => p.test(text))) return null;
  return {
    vulnerability: "Malicious Code Execution — encoded shell, web shell, or command execution invocation detected",
    weight: 50,
    threatType: "malware",
    evidence: linesWithMatch(text, MALWARE_EXEC_PATTERNS),
    confidence: 96,
    remediation: "Terminate malicious process trees, quarantine affected endpoints, and audit file uploads for unauthorized script execution.",
  };
}

function detectPortScanning(text: string): HeuristicMatch | null {
  if (!PORT_SCAN_PATTERNS.some((p) => p.test(text))) return null;
  return {
    vulnerability: "Network Reconnaissance — multi-port probing or automated port sweep detected",
    weight: 35,
    threatType: "lateral_movement",
    evidence: linesWithMatch(text, PORT_SCAN_PATTERNS),
    confidence: 92,
    remediation: "Block reconnaissance source IP at border firewall and review exposed network services.",
  };
}

function detectDosAttack(text: string): HeuristicMatch | null {
  if (!DOS_PATTERNS.some((p) => p.test(text))) return null;
  return {
    vulnerability: "Denial of Service — volumetric network flood or TCP SYN flood detected",
    weight: 45,
    threatType: "unknown",
    evidence: linesWithMatch(text, DOS_PATTERNS),
    confidence: 94,
    remediation: "Activate rate-limiting, upstream traffic scrubbing, and SYN cookies to mitigate flood attacks.",
  };
}

const DETECTORS = [
  detectSqlInjection,
  detectXss,
  detectPathTraversal,
  detectSensitiveFileAccess,
  detectBruteForce,
  detectMalwareExecution,
  detectPortScanning,
  detectDosAttack,
  detectSuspiciousActivity,
];

/* =========================
   Local heuristics engine
========================= */

const BASELINE_RISK_SCORE = 10;

/**
 * Pure, synchronous, offline detection pass — no network calls. Runs actual
 * regex/heuristic pattern matching against raw text (a log line, a pasted
 * payload, a chat message) and returns the same schema the Gemini path uses,
 * so callers never need to branch on which engine produced the result.
 */
export function analyzeWithHeuristics(rawText: string): SecurityAnalysis {
  const text = String(rawText ?? "");
  const matches = DETECTORS.map((detect) => detect(text)).filter((m): m is HeuristicMatch => m !== null);

  const context = extractContext(text);
  const detections = matches.map((match) => {
    const riskScore = Math.min(100, match.weight + (match.threatType === "brute_force" ? 10 : 5));
    return {
      threatType: match.threatType,
      riskScore,
      confidence: match.confidence,
      severity: deriveSeverityFromRiskScore(riskScore),
      evidence: match.evidence,
      reasoning: match.vulnerability,
      recommendedAction: match.remediation,
      ...context,
    };
  });

  const riskScore = detections.length ? Math.max(...detections.map((detection) => detection.riskScore)) : 0;

  const vulnerabilities = matches.map((m) => m.vulnerability);

  const reasoning = matches.length
    ? `Evidence-based rule engine flagged ${matches.length} indicator(s): ${vulnerabilities.join("; ")}. Risk is derived from the highest supported candidate.`
    : "NO THREAT DETECTED: no supported suspicious indicator matched the supplied log.";

  const remediationSteps = matches.length
    ? matches.map((m) => m.remediation)
    : ["No action required — continue routine monitoring and periodic log review."];

  return { riskScore, vulnerabilities, reasoning, remediationSteps, detections };
}

/* =========================
   Gemini failover
========================= */

export const SOC_ANALYST_SYSTEM_PROMPT = `You are a Tier-3 Security Operations Center (SOC) analyst with deep expertise in threat detection, log forensics, and incident response.

You will be given a raw security log or user-submitted text (syslog, auth log, firewall log, JSON, CSV, or free text). Analyze it carefully and respond with STRICT, VALID JSON ONLY — no markdown, no commentary, no code fences.

The JSON object must contain exactly these fields:
- "riskScore": integer 0-100 representing overall threat severity (0 = benign, 100 = critical active compromise)
- "vulnerabilities": array of strings, each naming a specific vulnerability, attack pattern, or indicator of compromise found
- "reasoning": string explaining, in analyst language, why this input produced this risk score and what evidence supports it
- "remediationSteps": array of strings, each a concrete, actionable remediation or mitigation step, ordered by priority

Be precise and evidence-based. You are a verifier, not a generator: you may only confirm or explain the rule-engine candidates supplied with the log. Never add a new threat type, evidence item, or event that is absent from the actual log. /etc/passwd, /etc/shadow, and other sensitive file paths are Sensitive File Access, never Path Traversal unless the actual log contains a traversal sequence such as ../, ..\\, %2e%2e%2f, or an equivalent encoded sequence. If no candidates are supplied, return an empty vulnerabilities array, riskScore 0, and say NO THREAT DETECTED in reasoning.`;

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

/**
 * The single entry point every route should call. Tries live Gemini
 * inference first when a key is configured; falls back to the local
 * heuristics engine on a missing key or any Gemini failure, so callers
 * never have to handle a thrown error themselves.
 */
export async function runSecurityAnalysis(
  rawText: string
): Promise<SecurityAnalysis & { source: AnalysisSource }> {
  const ruleAnalysis = analyzeWithHeuristics(rawText);
  if (!ruleAnalysis.detections.length) {
    return { ...ruleAnalysis, source: "heuristics" };
  }

  if (!process.env.GEMINI_API_KEY?.trim()) {
    return { ...ruleAnalysis, source: "heuristics" };
  }

  try {
    const verificationPrompt = `RULE-ENGINE CANDIDATES (authoritative; do not add to this list):
${JSON.stringify(ruleAnalysis.detections, null, 2)}

ACTUAL LOG DATA (the only event source):
<log>
${rawText}
</log>

Verify only the candidates supported by exact events in ACTUAL LOG DATA. Return JSON matching the requested schema.`;
    const raw = await generateJson(SOC_ANALYST_SYSTEM_PROMPT, verificationPrompt);
    return {
      ...ruleAnalysis,
      riskScore: ruleAnalysis.riskScore,
      vulnerabilities: ruleAnalysis.vulnerabilities,
      reasoning: raw.reasoning ? `${ruleAnalysis.reasoning} AI verification: ${raw.reasoning}` : ruleAnalysis.reasoning,
      remediationSteps: ruleAnalysis.remediationSteps,
      source: "gemini",
    };
  } catch (error) {
    console.error("[SecurityEngine] Gemini call failed, falling back to local heuristics:", error);
    return { ...ruleAnalysis, source: "heuristics" };
  }
}

/* =========================
   Derived-field helpers (shared across routes)
========================= */

export function deriveSeverityFromRiskScore(score: number): Severity {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 30) return "medium";
  return "low";
}

export function mapVulnerabilitiesToThreatType(vulnerabilities: string[]): ThreatType {
  const joined = vulnerabilities.join(" ").toLowerCase();
  if (joined.includes("brute force") || joined.includes("authentication failure")) return "brute_force";
  if (joined.includes("sensitive file access")) return "sensitive_file_access";
  if (joined.includes("sql injection")) return "sql_injection";
  if (joined.includes("path traversal")) return "path_traversal";
  if (joined.includes("cross-site scripting") || joined.includes("xss") || joined.includes("malicious code") || joined.includes("web shell") || joined.includes("encoded shell")) return "malware";
  if (joined.includes("port scanning") || joined.includes("reconnaissance")) return "lateral_movement";
  if (joined.includes("denial of service") || joined.includes("flood")) return "unknown";
  if (joined.includes("suspicious activity")) return "unknown";
  return "unknown";
}

export function getMitreIdsForVulnerabilities(vulnerabilities: string[]): string[] {
  const joined = vulnerabilities.join(" ").toLowerCase();
  const ids: string[] = [];
  if (joined.includes("sql injection")) ids.push("T1190");
  if (joined.includes("cross-site scripting") || joined.includes("xss")) ids.push("T1059.007");
  if (joined.includes("brute force")) ids.push("T1110");
  if (joined.includes("path traversal")) ids.push("T1006");
  if (joined.includes("malicious code") || joined.includes("web shell") || joined.includes("encoded shell")) ids.push("T1059.001", "T1505.003");
  if (joined.includes("port scanning") || joined.includes("reconnaissance")) ids.push("T1046");
  if (joined.includes("denial of service") || joined.includes("flood")) ids.push("T1498");
  return ids;
}

export interface NormalizedLog {
  timestamp: string;
  sourceIp?: string;
  destinationIp?: string;
  userId?: string;
  eventType: string;
  severity: Severity;
  description: string;
  additionalContext: Record<string, unknown>;
}

/**
 * Offline replacement for the Gemini-based log normalizer — extracts the
 * same field shape via regex so log upload keeps working with no API key.
 */
export function normalizeLogHeuristically(rawLog: string, sourceType: string): NormalizedLog {
  const text = String(rawLog ?? "");
  const ipMatches = text.match(new RegExp(IP_RE, "g")) || [];
  const userMatch = text.match(/(?:user|for)\s+([a-zA-Z0-9_.-]+)/i);
  const analysis = analyzeWithHeuristics(text);

  let eventType = "network_connection";
  if (AUTH_FAILURE_RE.test(text)) {
    eventType = "authentication_failure";
  } else if (XSS_PATTERNS.some((p) => p.test(text))) {
    eventType = "web_attack";
  } else if (SQLI_PATTERNS.some((p) => p.test(text))) {
    eventType = "sql_injection_attempt";
  } else if (PATH_TRAVERSAL_PATTERNS.some((p) => p.test(text))) {
    eventType = "path_traversal_attempt";
  } else if (SUSPICIOUS_ACTIVITY_PATTERNS.some((p) => p.test(text))) {
    eventType = "suspicious_activity";
  }

  return {
    timestamp: new Date().toISOString(),
    sourceIp: ipMatches[0],
    destinationIp: ipMatches[1],
    userId: userMatch?.[1],
    eventType,
    severity: deriveSeverityFromRiskScore(analysis.riskScore),
    description: text.length > 160 ? `${text.slice(0, 160)}...` : text,
    additionalContext: { sourceType, vulnerabilities: analysis.vulnerabilities, riskScore: analysis.riskScore },
  };
}

export function formatAnalysisAsMarkdown(analysis: SecurityAnalysis): string {
  const lines = [
    "**Local Threat Scan Result**",
    "",
    `**Risk Score:** ${analysis.riskScore}/100`,
    "",
    "**Vulnerabilities Detected:**",
    ...(analysis.vulnerabilities.length ? analysis.vulnerabilities.map((v) => `- ${v}`) : ["- None detected"]),
    "",
    `**Reasoning:** ${analysis.reasoning}`,
    "",
    "**Remediation Steps:**",
    ...analysis.remediationSteps.map((s, i) => `${i + 1}. ${s}`),
  ];
  return lines.join("\n");
}

export type EndpointTelemetryEvent = {
  endpointId: string;
  timestamp: string;
  eventType: string;
  source?: { ip?: string; port?: number };
  destination?: { ip?: string; port?: number };
  protocol?: string;
  process?: string;
  hostname?: string;
  status?: string;
  bytesSent?: number;
  bytesReceived?: number;
  durationSeconds?: number;
  confidence?: number;
  flags?: string[];
};

export function createEndpointEnrollmentToken(endpointName: string, organizationId: string): string {
  const raw = `${endpointName}:${organizationId}:${Date.now()}:${crypto.randomBytes(16).toString("hex")}`;
  return `endpoint_${crypto.createHash("sha256").update(raw).digest("hex")}`;
}

export function validateEndpointTelemetry(data: Partial<EndpointTelemetryEvent>): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (!data.endpointId || String(data.endpointId).trim().length === 0) {
    errors.push("endpointId is required");
  }

  if (!data.timestamp || Number.isNaN(Date.parse(String(data.timestamp)))) {
    errors.push("timestamp must be a valid ISO date string");
  }

  if (!data.eventType || String(data.eventType).trim().length === 0) {
    errors.push("eventType is required");
  }

  if (data.bytesSent !== undefined && typeof data.bytesSent !== "number") {
    errors.push("bytesSent must be a number when supplied");
  }

  if (data.bytesReceived !== undefined && typeof data.bytesReceived !== "number") {
    errors.push("bytesReceived must be a number when supplied");
  }

  return { valid: errors.length === 0, errors };
}

export function calculateEndpointRiskScore(events: Array<Partial<EndpointTelemetryEvent>>): number {
  if (!events.length) return 0;

  let score = 12;
  const suspiciousPortSet = new Set([22, 23, 3389, 445, 4444, 8080, 8443, 5900]);
  const suspiciousProcessSet = new Set(["powershell.exe", "cmd.exe", "rundll32.exe", "wmic.exe", "mshta.exe", "regsvr32.exe"]);

  for (const event of events) {
    if (!event) continue;
    const destinationPort = event.destination?.port;
    const processName = (event.process || "").toLowerCase();

    if (destinationPort && suspiciousPortSet.has(Number(destinationPort))) {
      score += 18;
    }

    if (processName && suspiciousProcessSet.has(processName)) {
      score += 14;
    }

    if (event.eventType === "dns_query" || event.eventType === "network_connection") {
      score += 6;
    }

    if (event.flags && event.flags.some((flag) => /suspicious|failed|blocked|repeated/i.test(flag))) {
      score += 12;
    }

    if (typeof event.confidence === "number") {
      score += Math.round(event.confidence * 20);
    }
  }

  return Math.min(100, score + Math.max(0, events.length - 1) * 4);
}

export function analyzeEndpointTelemetry(event: EndpointTelemetryEvent): {
  endpointId: string;
  timestamp: string;
  eventType: string;
  riskScore: number;
  severity: Severity;
  confidence: number;
  threatType: string;
  evidence: string[];
  description: string;
  recommendedInvestigation: string;
} {
  const sourceIp = event.source?.ip || "unknown";
  const destinationIp = event.destination?.ip || "unknown";
  const destinationPort = event.destination?.port;
  const processName = event.process || "unknown";
  const anomalyFactors: string[] = [];
  const suspiciousPorts = new Set([22, 23, 3389, 445, 4444, 8080, 8443, 5900]);
  const suspiciousProcesses = new Set(["powershell.exe", "cmd.exe", "rundll32.exe", "wmic.exe", "mshta.exe", "regsvr32.exe"]);

  if (destinationPort && suspiciousPorts.has(Number(destinationPort))) {
    anomalyFactors.push(`Connection to uncommon or sensitive port ${destinationPort}`);
  }

  if (processName && suspiciousProcesses.has(processName.toLowerCase())) {
    anomalyFactors.push(`Process ${processName} is frequently associated with suspicious remote activity`);
  }

  if (event.eventType === "dns_query") {
    anomalyFactors.push("DNS metadata indicates a new or repeated lookup pattern");
  }

  const confidence = Math.min(0.99, 0.55 + (event.confidence ?? 0.2) + anomalyFactors.length * 0.08);
  const riskScore = calculateEndpointRiskScore([event]);
  const severity = deriveSeverityFromRiskScore(riskScore);
  const description = anomalyFactors.length
    ? `Endpoint ${event.endpointId} displayed ${anomalyFactors.length} suspicious indicators connected to ${destinationIp}${destinationPort ? `:${destinationPort}` : ""}.`
    : `Endpoint ${event.endpointId} emitted metadata without strong evidence of malicious behavior.`;

  return {
    endpointId: event.endpointId,
    timestamp: event.timestamp || new Date().toISOString(),
    eventType: event.eventType,
    riskScore,
    severity,
    confidence: Number(confidence.toFixed(2)),
    threatType: anomalyFactors.length ? "unknown" : "low",
    evidence: anomalyFactors.length ? anomalyFactors : ["No malicious indicators met the confidence threshold."],
    description,
    recommendedInvestigation:
      anomalyFactors.length
        ? `Review the process ${processName} and destination ${destinationIp}${destinationPort ? `:${destinationPort}` : ""}, verify if the connection was authorized, and correlate with recent endpoint activity.`
        : "Continue routine monitoring; no immediate investigation required.",
  };
}
