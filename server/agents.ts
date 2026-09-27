import { generateJson, generateText } from "./gemini";
import { normalizeLogHeuristically } from "./services/securityEngine";

/**
 * Log Analyzer Agent
 * Normalizes raw security logs from diverse sources. Falls back to the
 * local regex-based normalizer whenever GEMINI_API_KEY is unset or the
 * live call fails, so log upload never drops every line for lack of a key.
 */
export async function analyzeLog(rawLog: string, sourceType: string) {
  if (!process.env.GEMINI_API_KEY?.trim()) {
    return normalizeLogHeuristically(rawLog, sourceType);
  }

  const systemPrompt = `You are a security log normalization expert. Your task is to parse raw security logs and extract key fields in a standardized format.

You must respond with valid JSON containing:
- timestamp: ISO 8601 format (e.g., "2026-01-23T12:34:56Z")
- sourceIp: Source IP address (IPv4 or IPv6)
- destinationIp: Destination IP address
- userId: User identifier (username, email, or ID)
- eventType: Type of event (e.g., "login_attempt", "file_access", "network_connection", "authentication_failure")
- severity: "low", "medium", "high", or "critical"
- description: Brief description of the event
- additionalContext: Object with any extra relevant fields`;

  const userPrompt = `Parse this raw security log from a ${sourceType} source and extract key fields:

${rawLog}

Respond ONLY with valid JSON, no other text.`;

  try {
    return await generateJson(systemPrompt, userPrompt);
  } catch (error) {
    console.error("[Log Analyzer] Gemini call failed, falling back to local heuristics:", error);
    return normalizeLogHeuristically(rawLog, sourceType);
  }
}

/**
 * Threat Classifier Agent
 * Classifies detected threats and assigns risk scores
 */
export async function classifyThreat(normalizedLog: Record<string, unknown>) {
  const systemPrompt = `You are a cybersecurity threat analyst expert. Your task is to analyze security logs and classify threats.

Threat classification options:
- phishing: Email-based social engineering attacks
- brute_force: Repeated login attempts with different passwords
- malware: Suspicious file execution or behavior
- lateral_movement: Unauthorized movement within network
- data_exfiltration: Unauthorized data access/transfer
- privilege_escalation: Unauthorized elevation of privileges
- unknown: Cannot classify

You must respond with valid JSON containing:
- threatType: Selected classification
- riskScore: 0-100 (0=no threat, 100=critical)
- confidence: 0-100 (confidence in classification)
- mitreAttackIds: Array of relevant MITRE ATT&CK IDs (e.g., ["T1566.002", "T1589.001"])
- indicators: Array of indicators of compromise
- reasoning: Explanation of classification`;

  const userPrompt = `Analyze this security log and classify the threat:

${JSON.stringify(normalizedLog, null, 2)}

Respond ONLY with valid JSON, no other text.`;

  try {
    return await generateJson(systemPrompt, userPrompt);
  } catch (error) {
    console.error("[Threat Classifier] Error:", error);
    throw error;
  }
}

/**
 * Response Planner Agent
 * Generates step-by-step incident response recommendations
 */
export async function planResponse(
  threatType: string,
  riskScore: number,
  affectedAssets: string[],
  organizationSize: string = "medium",
  industry: string = "technology"
) {
  const systemPrompt = `You are an incident response specialist. Your task is to generate step-by-step mitigation recommendations for detected threats.

For each action, provide:
- description: Clear action description
- estimatedHours: Time to complete (number)
- complexity: "low", "medium", or "high"
- responsibleTeam: Who should execute (e.g., "SOC", "Infrastructure", "Security", "Management")

You must respond with valid JSON containing:
- shortTermActions: Array of immediate actions (0-24 hours)
- longTermActions: Array of strategic actions (1-30 days)
- priority: "critical", "high", "medium", or "low"
- summary: Brief summary of the response plan`;

  const userPrompt = `Generate incident response recommendations for:
- Threat Type: ${threatType}
- Risk Score: ${riskScore}/100
- Affected Assets: ${affectedAssets.join(", ")}
- Organization Size: ${organizationSize}
- Industry: ${industry}

Respond ONLY with valid JSON, no other text.`;

  try {
    return await generateJson(systemPrompt, userPrompt);
  } catch (error) {
    console.error("[Response Planner] Error:", error);
    throw error;
  }
}

/**
 * Report Writer Agent
 * Generates comprehensive incident reports
 */
export async function generateReport(
  threatType: string,
  riskScore: number,
  detectionTime: string,
  affectedAssets: string[],
  technicalAnalysis: string,
  recommendations: Record<string, unknown>
) {
  const systemPrompt = `You are a cybersecurity report writer. Your task is to generate comprehensive incident reports.

You must respond with valid JSON containing:
- executiveSummary: 1-2 paragraph business-level summary
- technicalDetails: Detailed technical analysis
- immediateActions: List of immediate actions to take
- longTermImprovements: List of long-term improvements
- estimatedImpact: Business impact assessment
- references: List of relevant resources and standards`;

  const userPrompt = `Generate an incident report for:
- Threat Type: ${threatType}
- Risk Score: ${riskScore}/100
- Detection Time: ${detectionTime}
- Affected Assets: ${affectedAssets.join(", ")}

Technical Analysis:
${technicalAnalysis}

Recommendations:
${JSON.stringify(recommendations, null, 2)}

Respond ONLY with valid JSON, no other text.`;

  try {
    return await generateJson(systemPrompt, userPrompt);
  } catch (error) {
    console.error("[Report Writer] Error:", error);
    throw error;
  }
}

/**
 * SOC Copilot Agent
 * Answers questions about security logs and threats
 */
export async function socCopilotChat(
  userMessage: string,
  context: {
    recentThreats?: Array<{ threatType: string; riskScore: number }>;
    recentLogs?: Array<{ eventType: string; severity: string }>;
    organizationContext?: string;
  }
) {
  const systemPrompt = `You are a Security Operations Center (SOC) Copilot AI assistant. Your role is to help security analysts understand security logs, threats, and recommend actions.

You have access to:
- Recent threat detections
- Security log events
- Organization context

Provide clear, actionable insights. Be concise but thorough. Always explain the business impact and recommended next steps.`;

  const contextStr = context
    ? `Context:
Recent Threats: ${JSON.stringify(context.recentThreats || [])}
Recent Logs: ${JSON.stringify(context.recentLogs || [])}
Organization: ${context.organizationContext || "Unknown"}`
    : "";

  const userPrompt = `${contextStr}

User Question: ${userMessage}`;

  try {
    return await generateText(systemPrompt, userPrompt);
  } catch (error) {
    console.error("[SOC Copilot] Error:", error);
    throw error;
  }
}
