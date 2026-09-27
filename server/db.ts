import crypto from "crypto";
import fs from "fs";
import path from "path";
import { eq, and, desc, isNull, or, sql } from "drizzle-orm";
import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import {
  InsertUser,
  InsertThreatDetection,
  InsertSecurityLog,
  InsertIncidentRecommendation,
  InsertIncidentReport,
  InsertChatHistoryRecord,
  InsertEndpoint,
  InsertEndpointEnrollmentToken,
  InsertEndpointCredential,
  InsertEndpointTelemetry,
  User,
  Organization,
  Endpoint,
  EndpointTelemetry,
  SecurityLog,
  ThreatDetection,
  IncidentRecommendation,
  IncidentReport,
  ChatHistoryRecord,
  EndpointEnrollmentToken,
  EndpointCredential,
  users,
  passwordResetTokens,
  organizations,
  securityLogs,
  threatDetections,
  incidentRecommendations,
  incidentReports,
  chatHistory,
  endpoints,
  endpointEnrollmentTokens,
  endpointCredentials,
  endpointTelemetry,
} from "../drizzle/schema";
import { ENV } from "./_core/env";

let _db: ReturnType<typeof drizzle> | null = null;
let _dbConnectionVerified = false;
let _lastConnectionAttempt = 0;
let _connectionAttemptInProgress: Promise<ReturnType<typeof drizzle> | null> | null = null;
let _hasReportedOffline = false;
const CONNECTION_COOLDOWN_MS = 5 * 60 * 1000; // 5-minute cooldown between remote connection retries

/* =========================================================
   Local Persistent Stores for Users and Organizations
   ========================================================= */
const LOCAL_STORAGE_FILE = path.resolve(process.cwd(), ".local_storage.json");
const memoryUsers = new Map<string, User>(); // keyed by normalized openId / email
const memoryUsersById = new Map<number, User>();
let memoryUserIdCounter = 100;

const memoryOrgs = new Map<number, Organization>();
let memoryOrgIdCounter = 10;

// Initialize default organization
const defaultOrg: Organization = {
  id: 1,
  name: "CyberGuard SOC Core",
  ownerId: 1,
  industry: "Cybersecurity",
  maxLogsPerMonth: 100000,
  createdAt: new Date(),
  updatedAt: new Date(),
};
memoryOrgs.set(defaultOrg.id, defaultOrg);

// Seed pre-configured Admin account (matching OWNER_OPEN_ID) and Demo Analyst account
const adminEmail = (ENV.ownerOpenId || "vasuvora88@gmail.com").trim().toLowerCase();
const initialAdmin: User = {
  id: 1,
  openId: adminEmail,
  name: "SOC Administrator",
  email: adminEmail,
  loginMethod: "password",
  // bcrypt hash of "Admin@123456"
  passwordHash: "$2b$10$HW3ZN7NcaoSfzCR16Tr28OVEANo2ICrpAjToursBLSx0OMWQ2JIna",
  role: "admin",
  organizationId: 1,
  createdAt: new Date(),
  updatedAt: new Date(),
  lastSignedIn: new Date(),
};
memoryUsers.set(adminEmail, initialAdmin);
memoryUsersById.set(initialAdmin.id, initialAdmin);

const demoEmail = "analyst@cyberguard.ai";
const initialDemo: User = {
  id: 2,
  openId: demoEmail,
  name: "Cyber Security Analyst",
  email: demoEmail,
  loginMethod: "password",
  // bcrypt hash of "Analyst@123456"
  passwordHash: "$2b$10$05LGg4ulsNokghkYNDWYIeQqkTdHeQEzEFASK1s3TCkycWxrmsDAK",
  role: "user",
  organizationId: 1,
  createdAt: new Date(),
  updatedAt: new Date(),
  lastSignedIn: new Date(),
};
memoryUsers.set(demoEmail, initialDemo);
memoryUsersById.set(initialDemo.id, initialDemo);

/* =========================================================
   In-Memory Stores for Endpoints, Telemetry, Logs & Threats
   ========================================================= */
const memoryEndpoints = new Map<number, Endpoint>();
let memoryEndpointIdCounter = 10;

const memoryTelemetry: EndpointTelemetry[] = [];
let memoryTelemetryIdCounter = 1;

const memorySecurityLogs = new Map<number, SecurityLog>();
const memorySecurityLogsByHash = new Map<string, SecurityLog>();
let memoryLogIdCounter = 1;

const memoryThreats = new Map<number, ThreatDetection>();
let memoryThreatIdCounter = 10;

const memoryRecommendations = new Map<number, IncidentRecommendation>();
let memoryRecIdCounter = 1;

const memoryReports = new Map<number, IncidentReport>();
let memoryReportIdCounter = 1;

const memoryChatHistory: ChatHistoryRecord[] = [];
let memoryChatIdCounter = 1;

const memoryTokens = new Map<string, EndpointEnrollmentToken>();
let memoryTokenIdCounter = 1;

const memoryCredentials = new Map<number, EndpointCredential>();
let memoryCredIdCounter = 1;

// Seed initial enterprise workstations for employee monitoring
const defaultEndpoints: Endpoint[] = [
  {
    id: 1,
    organizationId: 1,
    name: "Sarah Jenkins — FIN-PC01 (Finance)",
    hostname: "FIN-PC01.corp.local",
    os: "Windows 11 Enterprise",
    agentVersion: "1.2.4",
    status: "online",
    lastSeen: new Date(),
    enrolledAt: new Date(Date.now() - 3600000 * 24),
    revokedAt: null,
    createdAt: new Date(Date.now() - 3600000 * 24),
  },
  {
    id: 2,
    organizationId: 1,
    name: "David Chen — DEV-SRV04 (DevOps)",
    hostname: "DEV-SRV04.cloud.internal",
    os: "Ubuntu 22.04 LTS",
    agentVersion: "1.2.4",
    status: "online",
    lastSeen: new Date(),
    enrolledAt: new Date(Date.now() - 3600000 * 48),
    revokedAt: null,
    createdAt: new Date(Date.now() - 3600000 * 48),
  },
  {
    id: 3,
    organizationId: 1,
    name: "Emily Watson — HR-LAPTOP-02 (HR)",
    hostname: "HR-LAPTOP-02.corp.local",
    os: "Windows 11 Enterprise",
    agentVersion: "1.2.4",
    status: "online",
    lastSeen: new Date(),
    enrolledAt: new Date(Date.now() - 3600000 * 12),
    revokedAt: null,
    createdAt: new Date(Date.now() - 3600000 * 12),
  },
  {
    id: 4,
    organizationId: 1,
    name: "Michael Ross — EXEC-MBP-01 (Sales/Exec)",
    hostname: "EXEC-MBP-01.local",
    os: "macOS Sonoma 14.5",
    agentVersion: "1.2.4",
    status: "online",
    lastSeen: new Date(),
    enrolledAt: new Date(Date.now() - 3600000 * 72),
    revokedAt: null,
    createdAt: new Date(Date.now() - 3600000 * 72),
  },
  {
    id: 5,
    organizationId: 1,
    name: "Marcus Vance — CONTRACTOR-WIN10 (Contractor)",
    hostname: "CONTRACTOR-WIN10.corp.local",
    os: "Windows 10 Pro",
    agentVersion: "1.2.3",
    status: "warning",
    lastSeen: new Date(),
    enrolledAt: new Date(Date.now() - 3600000 * 6),
    revokedAt: null,
    createdAt: new Date(Date.now() - 3600000 * 6),
  },
];

for (const ep of defaultEndpoints) {
  memoryEndpoints.set(ep.id, ep);
}

// Seed initial telemetry for all employee workstations
const seedTelemetryData: Array<{
  endpointId: number;
  sourceIp: string;
  destinationIp: string;
  destPort: number;
  protocol: string;
  process: string;
  hostname: string;
  riskScore: number;
  severity: "low" | "medium" | "high" | "critical";
  flags?: string[];
}> = [
  // Sarah Jenkins (Finance)
  { endpointId: 1, sourceIp: "192.168.1.105", destinationIp: "10.0.12.44", destPort: 443, protocol: "TCP", process: "excel.exe", hostname: "FIN-PC01", riskScore: 5, severity: "low" },
  { endpointId: 1, sourceIp: "192.168.1.105", destinationIp: "152.199.19.161", destPort: 443, protocol: "TCP", process: "chrome.exe", hostname: "FIN-PC01", riskScore: 8, severity: "low" },
  { endpointId: 1, sourceIp: "192.168.1.105", destinationIp: "52.96.166.130", destPort: 993, protocol: "TCP", process: "outlook.exe", hostname: "FIN-PC01", riskScore: 4, severity: "low" },

  // David Chen (DevOps)
  { endpointId: 2, sourceIp: "192.168.1.142", destinationIp: "10.0.4.15", destPort: 22, protocol: "TCP", process: "sshd", hostname: "DEV-SRV04", riskScore: 12, severity: "low" },
  { endpointId: 2, sourceIp: "192.168.1.142", destinationIp: "10.0.0.1", destPort: 6443, protocol: "TCP", process: "kubectl", hostname: "DEV-SRV04", riskScore: 10, severity: "low" },
  { endpointId: 2, sourceIp: "192.168.1.142", destinationIp: "140.82.121.4", destPort: 443, protocol: "TCP", process: "docker", hostname: "DEV-SRV04", riskScore: 5, severity: "low" },

  // Emily Watson (HR)
  { endpointId: 3, sourceIp: "192.168.1.118", destinationIp: "198.51.100.22", destPort: 443, protocol: "TCP", process: "workday_agent.exe", hostname: "HR-LAPTOP-02", riskScore: 6, severity: "low" },
  { endpointId: 3, sourceIp: "192.168.1.118", destinationIp: "54.203.111.4", destPort: 443, protocol: "TCP", process: "slack.exe", hostname: "HR-LAPTOP-02", riskScore: 5, severity: "low" },

  // Michael Ross (Executive)
  { endpointId: 4, sourceIp: "192.168.1.88", destinationIp: "170.114.10.8", destPort: 443, protocol: "UDP", process: "zoom.us", hostname: "EXEC-MBP-01", riskScore: 10, severity: "low" },
  { endpointId: 4, sourceIp: "192.168.1.88", destinationIp: "136.146.210.15", destPort: 443, protocol: "TCP", process: "salesforce_sync", hostname: "EXEC-MBP-01", riskScore: 8, severity: "low" },

  // Marcus Vance (Contractor) - SUSPICIOUS
  { endpointId: 5, sourceIp: "192.168.1.215", destinationIp: "185.220.101.5", destPort: 4444, protocol: "TCP", process: "powershell.exe", hostname: "CONTRACTOR-WIN10", riskScore: 88, severity: "critical", flags: ["suspicious", "c2_beacon", "metasploit"] },
  { endpointId: 5, sourceIp: "192.168.1.215", destinationIp: "192.168.1.1", destPort: 445, protocol: "TCP", process: "nmap.exe", hostname: "CONTRACTOR-WIN10", riskScore: 75, severity: "high", flags: ["suspicious", "port_scan"] },
  { endpointId: 5, sourceIp: "192.168.1.215", destinationIp: "93.184.216.34", destPort: 80, protocol: "TCP", process: "chrome.exe", hostname: "CONTRACTOR-WIN10", riskScore: 25, severity: "low" },
];

for (const s of seedTelemetryData) {
  memoryTelemetry.push({
    id: memoryTelemetryIdCounter++,
    organizationId: 1,
    endpointId: s.endpointId,
    eventType: "network_connection",
    sourceIp: s.sourceIp,
    destinationIp: s.destinationIp,
    protocol: s.protocol,
    processName: s.process,
    riskScore: String(s.riskScore),
    confidence: "90.00",
    severity: s.severity,
    eventData: {
      destinationPort: s.destPort,
      sourcePort: 49000 + s.endpointId * 100,
      hostname: s.hostname,
      process: s.process,
      flags: s.flags || [],
    },
    createdAt: new Date(Date.now() - Math.floor(Math.random() * 60000)),
  });
}

// Seed initial threat detection on Marcus Vance's PC
const initialThreat: ThreatDetection = {
  id: 1,
  organizationId: 1,
  logId: 1,
  threatType: "malware",
  riskScore: "88.00",
  confidence: "92.00",
  mitreAttackIds: ["T1071.001", "T1059.001"],
  indicators: ["185.220.101.5:4444", "powershell.exe -enc", "CONTRACTOR-WIN10"],
  affectedAssets: {
    hostname: "CONTRACTOR-WIN10.corp.local",
    sourceIp: "192.168.1.215",
    destinationIp: "185.220.101.5",
    userId: "marcus.vance",
    severity: "critical",
  },
  description: "C2 Reverse Shell Beaconing detected over TCP port 4444 on Marcus Vance contractor laptop.",
  aiAnalysis: "Threat identified via behavioral socket telemetry. Workstation established outbound session to known C2 indicator 185.220.101.5 on port 4444 with encoded PowerShell invocation. Immediate network isolation recommended.",
  status: "new",
  createdAt: new Date(Date.now() - 3600000 * 2),
  updatedAt: new Date(Date.now() - 3600000 * 2),
};
memoryThreats.set(initialThreat.id, initialThreat);

const secondThreat: ThreatDetection = {
  id: 2,
  organizationId: 1,
  logId: 2,
  threatType: "sql_injection",
  riskScore: "76.00",
  confidence: "88.00",
  mitreAttackIds: ["T1190", "T1059"],
  indicators: ["' UNION SELECT username, password_hash FROM auth_users--", "192.168.1.45"],
  affectedAssets: {
    hostname: "FIN-PC01.corp.local",
    sourceIp: "192.168.1.45",
    userId: "sarah.jenkins",
    severity: "high",
  },
  description: "Exploitation attempt targeting internal ERP finance portal with union-based SQL injection.",
  aiAnalysis: "Payload contains tautological boolean injections and UNION-based extraction against accounting database endpoints. WAF rules triggered and attacker IP flagged.",
  status: "investigating",
  createdAt: new Date(Date.now() - 3600000 * 5),
  updatedAt: new Date(Date.now() - 3600000 * 5),
};
memoryThreats.set(secondThreat.id, secondThreat);

const thirdThreat: ThreatDetection = {
  id: 3,
  organizationId: 1,
  logId: 3,
  threatType: "brute_force",
  riskScore: "62.00",
  confidence: "85.00",
  mitreAttackIds: ["T1110.001", "T1078"],
  indicators: ["SSH failed logins > 140/min", "root, admin, deploy", "192.168.1.102"],
  affectedAssets: {
    hostname: "DEV-SRV04.cloud.internal",
    sourceIp: "192.168.1.102",
    userId: "david.chen",
    severity: "medium",
  },
  description: "Automated credential stuffing against internal staging DevOps server via SSH.",
  aiAnalysis: "Detected 140 rapid authentication failures using dictionary passwords within 60 seconds against port 22. Fail2ban trigger active.",
  status: "new",
  createdAt: new Date(Date.now() - 3600000 * 8),
  updatedAt: new Date(Date.now() - 3600000 * 8),
};
memoryThreats.set(thirdThreat.id, thirdThreat);

// Seed pre-generated initial incident report for Marcus Vance C2 incident
const initialReport: IncidentReport = {
  id: 1,
  organizationId: 1,
  threatDetectionId: 1,
  reportType: "combined",
  title: "SOC Incident Dossier // CG-INC-2026-8842 - MALWARE C2 BEACONING",
  executiveSummary: "CyberGuard AI autonomous security reasoning detected active Command and Control (C2) beaconing over TCP port 4444 originating from Marcus Vance's contractor workstation (CONTRACTOR-WIN10, 192.168.1.215). Malicious payload matches Metasploit reverse TCP handler signatures. Host was quarantined to prevent lateral traversal.",
  technicalAnalysis: JSON.stringify({
    threatType: "malware",
    riskScore: "88.00",
    confidence: "92.00",
    mitreAttackIds: ["T1071.001", "T1059.001", "T1573"],
    indicators: ["185.220.101.5:4444", "powershell.exe -enc", "CONTRACTOR-WIN10"],
    affectedAssets: {
      hostname: "CONTRACTOR-WIN10.corp.local",
      sourceIp: "192.168.1.215",
      destinationIp: "185.220.101.5",
      userId: "marcus.vance",
      severity: "critical",
    },
  }),
  recommendations: JSON.stringify({
    immediate: [
      "Isolate CONTRACTOR-WIN10 from corporate VLAN immediately to stop active beaconing.",
      "Terminate malicious process tree (PID: 4921, powershell.exe).",
      "Revoke contractor VPN access and Active Directory account marcus.vance.",
    ],
    containment: [
      "Capture volatile RAM dump and forensic disk snapshot for forensic analysis.",
      "Block C2 destination IP 185.220.101.5 on perimeter firewall and DNS sinkhole.",
      "Audit subnet 192.168.1.0/24 for lateral SMB probes and Pass-the-Hash attempts.",
    ],
    longTerm: [
      "Enforce strict Application Whitelisting (WDAC) across all external contractor devices.",
      "Disallow contractor workstations direct corporate LAN connectivity without isolated VDI.",
      "Deploy behavioral heuristics rules to flag encoded PowerShell invocations exceeding 100 characters.",
    ],
  }),
  pdfUrl: null,
  generatedBy: 1,
  createdAt: new Date(Date.now() - 3600000 * 2),
};
memoryReports.set(initialReport.id, initialReport);
memoryReportIdCounter = 2;

// Seed recommendations for initial threats
const initialRec: IncidentRecommendation = {
  id: 1,
  threatDetectionId: 1,
  organizationId: 1,
  shortTermActions: [
    {
      description: "Isolate CONTRACTOR-WIN10 from corporate VLAN and terminate reverse shell process.",
      estimatedHours: 1,
      complexity: "medium",
      responsibleTeam: "SOC",
    },
  ],
  longTermActions: [
    {
      description: "Enforce zero-trust posture checks and restrict contractor PowerShell execution policies.",
      estimatedHours: 16,
      complexity: "high",
      responsibleTeam: "Security Engineering",
    },
  ],
  estimatedEffort: "17 hours",
  priority: "critical",
  aiGeneratedText: "Reverse shell beaconing detected. Host isolation and credential revocation required immediately.",
  status: "pending",
  createdAt: new Date(Date.now() - 3600000 * 2),
  updatedAt: new Date(Date.now() - 3600000 * 2),
};
memoryRecommendations.set(initialRec.threatDetectionId, initialRec);

const secondRec: IncidentRecommendation = {
  id: 2,
  threatDetectionId: 2,
  organizationId: 1,
  shortTermActions: [
    {
      description: "Block attacker IP 192.168.1.45 at edge WAF and enforce parameterized query filters.",
      estimatedHours: 1,
      complexity: "low",
      responsibleTeam: "SOC",
    },
  ],
  longTermActions: [
    {
      description: "Perform code audit of ERP accounting database query handlers.",
      estimatedHours: 8,
      complexity: "medium",
      responsibleTeam: "Engineering",
    },
  ],
  estimatedEffort: "9 hours",
  priority: "high",
  aiGeneratedText: "SQL injection attempt detected against internal ERP portal. WAF rules triggered.",
  status: "pending",
  createdAt: new Date(Date.now() - 3600000 * 5),
  updatedAt: new Date(Date.now() - 3600000 * 5),
};
memoryRecommendations.set(secondRec.threatDetectionId, secondRec);
memoryRecIdCounter = 3;

function loadLocalStorage() {
  try {
    if (fs.existsSync(LOCAL_STORAGE_FILE)) {
      const data = JSON.parse(fs.readFileSync(LOCAL_STORAGE_FILE, "utf-8"));
      if (Array.isArray(data.users)) {
        for (const u of data.users) {
          const userObj: User = {
            ...u,
            createdAt: new Date(u.createdAt),
            updatedAt: new Date(u.updatedAt),
            lastSignedIn: new Date(u.lastSignedIn),
          };
          memoryUsers.set(userObj.openId.toLowerCase(), userObj);
          if (userObj.email) memoryUsers.set(userObj.email.toLowerCase(), userObj);
          memoryUsersById.set(userObj.id, userObj);
          if (userObj.id >= memoryUserIdCounter) memoryUserIdCounter = userObj.id + 1;
        }
      }
      if (Array.isArray(data.orgs)) {
        for (const o of data.orgs) {
          const orgObj: Organization = {
            ...o,
            createdAt: new Date(o.createdAt),
            updatedAt: new Date(o.updatedAt),
          };
          memoryOrgs.set(orgObj.id, orgObj);
          if (orgObj.id >= memoryOrgIdCounter) memoryOrgIdCounter = orgObj.id + 1;
        }
      }
    }
  } catch {
    // Ignore storage read errors
  }
}

function saveLocalStorage() {
  try {
    const data = {
      users: Array.from(memoryUsersById.values()),
      orgs: Array.from(memoryOrgs.values()),
    };
    fs.writeFileSync(LOCAL_STORAGE_FILE, JSON.stringify(data, null, 2), "utf-8");
  } catch {
    // Ignore storage write errors
  }
}

// Load any previously persisted local records on module start
loadLocalStorage();

async function attemptConnect(): Promise<ReturnType<typeof drizzle> | null> {
  if (!process.env.DATABASE_URL) return null;
  _lastConnectionAttempt = Date.now();

  try {
    const client = postgres(process.env.DATABASE_URL, {
      connect_timeout: 2, // 2s timeout
      idle_timeout: 20,
      max_lifetime: 60 * 30,
      ssl: "require",
    });
    const db = drizzle(client);

    await client`SELECT 1`;

    _db = db;
    _dbConnectionVerified = true;
    _hasReportedOffline = false;
    console.info("[Database] Remote database connected and verified.");
    return _db;
  } catch (error) {
    _db = null;
    _dbConnectionVerified = false;
    if (!_hasReportedOffline) {
      _hasReportedOffline = true;
      const message = error instanceof Error ? error.message : String(error);
      console.warn(`[Database] Remote database unreachable (${message}). Local mode active.`);
    }
    return null;
  } finally {
    _connectionAttemptInProgress = null;
  }
}

// Lazily create the drizzle instance with single-flight check & non-blocking fallback.
export async function getDb() {
  if (_db && _dbConnectionVerified) return _db;

  if (!process.env.DATABASE_URL) {
    return null;
  }

  // If already known to be offline and within cooldown, return null immediately without delay
  if (_hasReportedOffline && Date.now() - _lastConnectionAttempt < CONNECTION_COOLDOWN_MS) {
    return null;
  }

  // If an attempt is already running, return null immediately so concurrent queries are not delayed
  if (_connectionAttemptInProgress) {
    return null;
  }

  _connectionAttemptInProgress = attemptConnect();
  return _connectionAttemptInProgress;
}

/**
 * Returns the DB instance if available, or null for fallback.
 */
export async function requireDb() {
  return getDb();
}

export async function upsertUser(user: InsertUser): Promise<void> {
  if (!user.openId) {
    throw new Error("User openId is required for upsert");
  }

  const normalizedOpenId = user.openId.trim().toLowerCase();
  const existing = memoryUsers.get(normalizedOpenId);
  const now = new Date();
  const userId = existing ? existing.id : (user.id ?? memoryUserIdCounter++);
  const userRole = user.role ?? (normalizedOpenId === adminEmail ? "admin" : (existing?.role ?? "user"));

  const updated: User = {
    id: userId,
    openId: normalizedOpenId,
    name: user.name !== undefined ? (user.name ?? null) : (existing?.name ?? null),
    email: user.email !== undefined ? (user.email ?? null) : (existing?.email ?? normalizedOpenId),
    loginMethod: user.loginMethod !== undefined ? (user.loginMethod ?? null) : (existing?.loginMethod ?? "password"),
    passwordHash: user.passwordHash !== undefined ? (user.passwordHash ?? null) : (existing?.passwordHash ?? null),
    role: userRole,
    organizationId: user.organizationId !== undefined ? (user.organizationId ?? null) : (existing?.organizationId ?? 1),
    createdAt: existing ? existing.createdAt : now,
    updatedAt: now,
    lastSignedIn: user.lastSignedIn ?? now,
  };

  memoryUsers.set(normalizedOpenId, updated);
  if (updated.email) {
    memoryUsers.set(updated.email.toLowerCase(), updated);
  }
  memoryUsersById.set(updated.id, updated);
  saveLocalStorage();

  const db = await getDb();
  if (!db) {
    return;
  }

  try {
    const values: Partial<InsertUser> = {
      openId: normalizedOpenId,
    };
    const updateSet: Record<string, unknown> = {};

    const textFields = ["name", "email", "loginMethod", "passwordHash"] as const;
    type TextField = (typeof textFields)[number];

    const assignNullable = (field: TextField) => {
      const value = user[field];
      if (value === undefined) return;
      const normalized = value ?? null;
      values[field] = normalized;
      updateSet[field] = normalized;
    };

    textFields.forEach(assignNullable);

    if (user.organizationId !== undefined) {
      values.organizationId = user.organizationId ?? null;
      updateSet.organizationId = user.organizationId ?? null;
    }

    if (user.lastSignedIn !== undefined) {
      values.lastSignedIn = user.lastSignedIn;
      updateSet.lastSignedIn = user.lastSignedIn;
    }
    if (user.role !== undefined) {
      values.role = user.role;
      updateSet.role = user.role;
    } else if (normalizedOpenId === adminEmail) {
      values.role = "admin";
      updateSet.role = "admin";
    }

    if (!values.lastSignedIn) {
      values.lastSignedIn = new Date();
    }

    if (Object.keys(updateSet).length === 0) {
      updateSet.lastSignedIn = new Date();
    }

    await db
      .insert(users)
      .values(values as InsertUser)
      .onConflictDoUpdate({
        target: users.openId,
        set: updateSet,
      });
  } catch (error) {
    console.warn("[Database] Failed to upsert user to remote DB, in-memory updated:", error instanceof Error ? error.message : String(error));
  }
}

export async function getUserById(id: number) {
  const db = await getDb();
  if (db) {
    try {
      const result = await db
        .select()
        .from(users)
        .where(eq(users.id, id))
        .limit(1);

      if (result.length > 0) {
        memoryUsersById.set(result[0].id, result[0]);
        memoryUsers.set(result[0].openId.toLowerCase(), result[0]);
        return result[0];
      }
    } catch {
      // Fallback to in-memory store
    }
  }

  return memoryUsersById.get(id);
}

export async function getUserByOpenId(openId: string) {
  const normalized = openId.trim().toLowerCase();
  const db = await getDb();
  if (db) {
    try {
      const result = await db
        .select()
        .from(users)
        .where(or(eq(users.openId, normalized), eq(users.email, normalized)))
        .limit(1);

      if (result.length > 0) {
        memoryUsers.set(normalized, result[0]);
        memoryUsersById.set(result[0].id, result[0]);
        return result[0];
      }
    } catch {
      // Fallback to in-memory store
    }
  }

  return memoryUsers.get(normalized);
}

const passwordResetTokenMemory = new Map<string, {
  userOpenId: string;
  userId: number;
  tokenHash: string;
  expiresAt: number;
  usedAt?: number;
  revokedAt?: number;
}>();

const passwordResetTokenByUser = new Map<string, {
  userOpenId: string;
  userId: number;
  tokenHash: string;
  expiresAt: number;
  usedAt?: number;
  revokedAt?: number;
}>();

export function generatePasswordResetToken(): string {
  return `pwreset_${crypto.randomBytes(32).toString("hex")}`;
}

export function hashPasswordResetToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

export function isPasswordResetTokenExpired(expiresAt: Date | number): boolean {
  const expiryMs = typeof expiresAt === "number" ? expiresAt : expiresAt.getTime();
  return Date.now() > expiryMs;
}

export async function storePasswordResetToken(params: {
  userOpenId: string;
  userId: number;
  token: string;
  expiresAt: Date | number;
  usedAt?: Date | number;
  revokedAt?: Date | number;
}): Promise<{ id: number; userId: number; tokenHash: string; expiresAt: Date; usedAt?: Date | null; revokedAt?: Date | null } | undefined> {
  const normalizedUserOpenId = params.userOpenId.trim().toLowerCase();
  const tokenHash = hashPasswordResetToken(params.token);
  const expires = new Date(params.expiresAt);
  const used = params.usedAt ? new Date(params.usedAt) : null;
  const revoked = params.revokedAt ? new Date(params.revokedAt) : null;

  const db = await getDb();
  if (db) {
    try {
      await db.delete(passwordResetTokens).where(eq(passwordResetTokens.userId, params.userId));
      const [inserted] = await db
        .insert(passwordResetTokens)
        .values({
          userId: params.userId,
          tokenHash,
          expiresAt: expires,
          usedAt: used ?? undefined,
          revokedAt: revoked ?? undefined,
        })
        .returning();

      if (inserted) {
        return {
          id: inserted.id,
          userId: inserted.userId,
          tokenHash: inserted.tokenHash,
          expiresAt: inserted.expiresAt,
          usedAt: inserted.usedAt ?? undefined,
          revokedAt: inserted.revokedAt ?? undefined,
        };
      }
    } catch (error) {
      console.error("[PASSWORD_RESET] DB token storage failed; falling back to in-memory store", {
        userId: params.userId,
        userOpenId: params.userOpenId,
        error: error instanceof Error ? error.message : "unknown",
      });
    }
  }

  const entry = {
    userOpenId: params.userOpenId,
    userId: params.userId,
    tokenHash,
    expiresAt: expires.getTime(),
    usedAt: used?.getTime(),
    revokedAt: revoked?.getTime(),
  };

  passwordResetTokenMemory.set(tokenHash, entry);
  passwordResetTokenByUser.set(normalizedUserOpenId, entry);

  return {
    id: -1,
    userId: params.userId,
    tokenHash,
    expiresAt: expires,
    usedAt: used ?? undefined,
    revokedAt: revoked ?? undefined,
  };
}

export async function getPasswordResetTokenByHash(tokenHash: string): Promise<
  | { id: number; userId: number; tokenHash: string; expiresAt: Date; usedAt: Date | null; revokedAt: Date | null; userOpenId: string }
  | undefined
> {
  const db = await getDb();
  if (db) {
    try {
      const result = await db
        .select()
        .from(passwordResetTokens)
        .where(eq(passwordResetTokens.tokenHash, tokenHash))
        .limit(1);

      if (result[0]) {
        const user = await getUserById(result[0].userId);
        return {
          id: result[0].id,
          userId: result[0].userId,
          tokenHash: result[0].tokenHash,
          expiresAt: result[0].expiresAt,
          usedAt: result[0].usedAt ?? null,
          revokedAt: result[0].revokedAt ?? null,
          userOpenId: user?.openId ?? "",
        };
      }
    } catch (error) {
      console.warn("[PASSWORD_RESET] token lookup failed in DB, checking in-memory fallback", {
        error: error instanceof Error ? error.message : "unknown",
      });
    }
  }

  const memoryEntry = passwordResetTokenMemory.get(tokenHash);
  if (!memoryEntry) return undefined;

  return {
    id: -1,
    userId: memoryEntry.userId,
    tokenHash: memoryEntry.tokenHash,
    expiresAt: new Date(memoryEntry.expiresAt),
    usedAt: memoryEntry.usedAt ? new Date(memoryEntry.usedAt) : null,
    revokedAt: memoryEntry.revokedAt ? new Date(memoryEntry.revokedAt) : null,
    userOpenId: memoryEntry.userOpenId,
  };
}

export async function getPasswordResetTokenForUser(userOpenId: string): Promise<
  | { id: number; userId: number; tokenHash: string; expiresAt: Date; usedAt: Date | null; revokedAt: Date | null; userOpenId: string }
  | undefined
> {
  const normalizedUserOpenId = userOpenId.trim().toLowerCase();

  const byUserEntry = passwordResetTokenByUser.get(normalizedUserOpenId);
  if (byUserEntry) {
    return {
      id: -1,
      userId: byUserEntry.userId,
      tokenHash: byUserEntry.tokenHash,
      expiresAt: new Date(byUserEntry.expiresAt),
      usedAt: byUserEntry.usedAt ? new Date(byUserEntry.usedAt) : null,
      revokedAt: byUserEntry.revokedAt ? new Date(byUserEntry.revokedAt) : null,
      userOpenId: byUserEntry.userOpenId,
    };
  }

  const user = await getUserByOpenId(userOpenId);
  if (!user) {
    return undefined;
  }

  const db = await getDb();
  if (db) {
    try {
      const result = await db
        .select()
        .from(passwordResetTokens)
        .where(eq(passwordResetTokens.userId, user.id))
        .orderBy(desc(passwordResetTokens.createdAt))
        .limit(1);

      if (result[0]) {
        return {
          id: result[0].id,
          userId: result[0].userId,
          tokenHash: result[0].tokenHash,
          expiresAt: result[0].expiresAt,
          usedAt: result[0].usedAt ?? null,
          revokedAt: result[0].revokedAt ?? null,
          userOpenId: user.openId,
        };
      }
    } catch (error) {
      console.warn("[PASSWORD_RESET] user token lookup failed in DB, checking in-memory fallback", {
        error: error instanceof Error ? error.message : "unknown",
      });
    }
  }

  for (const entry of Array.from(passwordResetTokenMemory.values())) {
    if (entry.userOpenId.toLowerCase() === normalizedUserOpenId) {
      return {
        id: -1,
        userId: entry.userId,
        tokenHash: entry.tokenHash,
        expiresAt: new Date(entry.expiresAt),
        usedAt: entry.usedAt ? new Date(entry.usedAt) : null,
        revokedAt: entry.revokedAt ? new Date(entry.revokedAt) : null,
        userOpenId: entry.userOpenId,
      };
    }
  }

  return undefined;
}

export async function invalidatePasswordResetToken(tokenHash: string): Promise<void> {
  const db = await getDb();
  if (db) {
    try {
      await db
        .update(passwordResetTokens)
        .set({ usedAt: new Date(), revokedAt: new Date() })
        .where(eq(passwordResetTokens.tokenHash, tokenHash));
    } catch (error) {
      console.warn("[PASSWORD_RESET] token invalidation failed in DB", {
        error: error instanceof Error ? error.message : "unknown",
      });
    }
  }

  const memoryEntry = passwordResetTokenMemory.get(tokenHash);
  if (memoryEntry) {
    memoryEntry.usedAt = Date.now();
    memoryEntry.revokedAt = Date.now();
  }

  for (const [userKey, entry] of Array.from(passwordResetTokenByUser.entries())) {
    if (entry.tokenHash === tokenHash) {
      entry.usedAt = Date.now();
      entry.revokedAt = Date.now();
      passwordResetTokenByUser.set(userKey, entry);
    }
  }
}

export async function hasValidPasswordResetTokenForUser(userId: number, tokenHash: string): Promise<boolean> {
  const entry = await getPasswordResetTokenByHash(tokenHash);
  if (!entry || entry.userId !== userId) return false;
  if (entry.revokedAt || entry.usedAt) return false;
  if (isPasswordResetTokenExpired(entry.expiresAt)) return false;
  return true;
}

// Organization queries
export async function createOrganization(
  name: string,
  ownerId: number,
  industry?: string
) {
  const db = await getDb();
  if (db) {
    try {
      const result = await db
        .insert(organizations)
        .values({
          name,
          ownerId,
          industry,
        })
        .returning();
      if (result[0]) {
        memoryOrgs.set(result[0].id, result[0]);
        return result[0];
      }
    } catch (error) {
      console.warn("[Database] createOrganization remote DB insert failed, using in-memory store:", error instanceof Error ? error.message : String(error));
    }
  }

  const id = memoryOrgIdCounter++;
  const org: Organization = {
    id,
    name,
    ownerId,
    industry: industry ?? null,
    maxLogsPerMonth: 100000,
    createdAt: new Date(),
    updatedAt: new Date(),
  };
  memoryOrgs.set(id, org);
  saveLocalStorage();
  return org;
}

export async function getOrganizationById(id: number) {
  const db = await getDb();
  if (db) {
    try {
      const result = await db
        .select()
        .from(organizations)
        .where(eq(organizations.id, id))
        .limit(1);

      if (result.length > 0) {
        memoryOrgs.set(result[0].id, result[0]);
        return result[0];
      }
    } catch {
      // Fallback to in-memory store
    }
  }

  return memoryOrgs.get(id);
}

export async function getOrganizationByOwnerId(ownerId: number) {
  const db = await getDb();
  if (db) {
    try {
      const result = await db
        .select()
        .from(organizations)
        .where(eq(organizations.ownerId, ownerId))
        .limit(1);

      if (result.length > 0) {
        memoryOrgs.set(result[0].id, result[0]);
        return result[0];
      }
    } catch {
      // Fallback to in-memory store
    }
  }

  for (const org of Array.from(memoryOrgs.values())) {
    if (org.ownerId === ownerId) return org;
  }
  return undefined;
}

// Security logs queries
/**
 * Returns undefined (instead of throwing) when `logHash` already exists —
 * re-uploading byte-identical log content is an expected occurrence (a user
 * re-running the same test file, a retried upload), not a server error.
 */
export async function createSecurityLog(data: InsertSecurityLog) {
  const db = await getDb();
  if (!db) {
    if (data.logHash && memorySecurityLogsByHash.has(data.logHash)) {
      return undefined;
    }
    const logObj: SecurityLog = {
      id: memoryLogIdCounter++,
      organizationId: data.organizationId,
      sourceType: data.sourceType || "other",
      rawLog: data.rawLog || "",
      normalizedLog: data.normalizedLog || null,
      timestamp: data.timestamp ? new Date(data.timestamp) : new Date(),
      sourceIp: data.sourceIp || null,
      destinationIp: data.destinationIp || null,
      userId: data.userId || null,
      eventType: data.eventType || null,
      severity: (data.severity as any) || "low",
      logHash: data.logHash || null,
      createdAt: new Date(),
    };
    memorySecurityLogs.set(logObj.id, logObj);
    if (logObj.logHash) memorySecurityLogsByHash.set(logObj.logHash, logObj);
    return logObj;
  }

  const result = await db
    .insert(securityLogs)
    .values(data)
    .onConflictDoNothing({ target: securityLogs.logHash })
    .returning();
  return result[0];
}

export async function getSecurityLogByHash(logHash: string) {
  const db = await getDb();
  if (!db) return memorySecurityLogsByHash.get(logHash);

  const result = await db
    .select()
    .from(securityLogs)
    .where(eq(securityLogs.logHash, logHash))
    .limit(1);

  return result[0];
}

export async function getAnalyzedLogIds(organizationId: number): Promise<Set<number>> {
  const db = await getDb();
  if (!db) {
    const ids = new Set<number>();
    for (const t of Array.from(memoryThreats.values())) {
      if (t.organizationId === organizationId && t.logId) ids.add(t.logId);
    }
    return ids;
  }

  const rows = await db
    .select({ logId: threatDetections.logId })
    .from(threatDetections)
    .where(eq(threatDetections.organizationId, organizationId));

  return new Set(rows.map((row) => row.logId).filter((id): id is number => id !== null));
}

export async function getSecurityLogsByOrganization(
  organizationId: number,
  limit = 50,
  offset = 0
) {
  const db = await getDb();
  if (!db) {
    return Array.from(memorySecurityLogs.values())
      .filter((l) => l.organizationId === organizationId)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
      .slice(offset, offset + limit);
  }

  return await db
    .select()
    .from(securityLogs)
    .where(eq(securityLogs.organizationId, organizationId))
    .orderBy(desc(securityLogs.createdAt))
    .limit(limit)
    .offset(offset);
}

// Threat detection queries
export async function createThreatDetection(data: InsertThreatDetection) {
  const db = await getDb();
  if (!db) {
    const threatObj: ThreatDetection = {
      id: memoryThreatIdCounter++,
      organizationId: data.organizationId,
      logId: data.logId || null,
      threatType: (data.threatType as any) || "unknown",
      riskScore: data.riskScore ? String(data.riskScore) : "0",
      confidence: String(data.confidence || "0"),
      mitreAttackIds: (data.mitreAttackIds as string[]) || [],
      indicators: (data.indicators as string[]) || [],
      affectedAssets: data.affectedAssets || null,
      description: data.description || null,
      aiAnalysis: data.aiAnalysis || null,
      status: (data.status as any) || "new",
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    memoryThreats.set(threatObj.id, threatObj);
    return threatObj;
  }

  const result = await db.insert(threatDetections).values(data).returning();
  return result[0];
}

export async function getThreatDetectionByLogAndType(
  organizationId: number,
  logId: number,
  threatType: NonNullable<InsertThreatDetection["threatType"]>
) {
  const db = await getDb();
  if (!db) {
    for (const t of Array.from(memoryThreats.values())) {
      if (t.organizationId === organizationId && t.logId === logId && t.threatType === threatType) {
        return t;
      }
    }
    return undefined;
  }

  const result = await db
    .select()
    .from(threatDetections)
    .where(
      and(
        eq(threatDetections.organizationId, organizationId),
        eq(threatDetections.logId, logId),
        eq(threatDetections.threatType, threatType)
      )
    )
    .limit(1);

  return result[0];
}

export async function getThreatDetectionsByOrganization(
  organizationId: number,
  limit = 50,
  offset = 0
) {
  const db = await getDb();
  if (!db) {
    return Array.from(memoryThreats.values())
      .filter((t) => t.organizationId === organizationId)
      .sort((a, b) => Number(b.riskScore) - Number(a.riskScore))
      .slice(offset, offset + limit);
  }

  return await db
    .select()
    .from(threatDetections)
    .where(eq(threatDetections.organizationId, organizationId))
    .orderBy(desc(threatDetections.riskScore))
    .limit(limit)
    .offset(offset);
}

export async function getThreatDetectionById(id: number, organizationId?: number) {
  const db = await getDb();
  if (!db) {
    const t = memoryThreats.get(id);
    if (!t) return undefined;
    if (organizationId !== undefined && t.organizationId !== organizationId) return undefined;
    return t;
  }

  const conditions = organizationId !== undefined
    ? and(eq(threatDetections.id, id), eq(threatDetections.organizationId, organizationId))
    : eq(threatDetections.id, id);

  const result = await db
    .select()
    .from(threatDetections)
    .where(conditions)
    .limit(1);

  return result.length > 0 ? result[0] : undefined;
}

export async function updateThreatDetectionStatus(
  id: number,
  status: "new" | "investigating" | "confirmed" | "false_positive" | "resolved",
  organizationId?: number
) {
  const db = await getDb();
  if (!db) {
    const t = memoryThreats.get(id);
    if (t) {
      if (organizationId === undefined || t.organizationId === organizationId) {
        t.status = status;
        t.updatedAt = new Date();
      }
    }
    return;
  }

  const conditions = organizationId !== undefined
    ? and(eq(threatDetections.id, id), eq(threatDetections.organizationId, organizationId))
    : eq(threatDetections.id, id);

  return await db
    .update(threatDetections)
    .set({ status, updatedAt: new Date() })
    .where(conditions);
}

export async function deleteThreatDetection(id: number, organizationId: number) {
  const db = await getDb();
  if (!db) {
    const t = memoryThreats.get(id);
    if (t && t.organizationId === organizationId) {
      memoryThreats.delete(id);
      memoryRecommendations.delete(id);
    }
    return;
  }

  await db
    .delete(incidentRecommendations)
    .where(
      and(
        eq(incidentRecommendations.threatDetectionId, id),
        eq(incidentRecommendations.organizationId, organizationId)
      )
    );

  return db
    .delete(threatDetections)
    .where(and(eq(threatDetections.id, id), eq(threatDetections.organizationId, organizationId)));
}

export async function deleteAllThreatDetections(organizationId: number) {
  const db = await getDb();
  if (!db) {
    for (const [id, t] of Array.from(memoryThreats.entries())) {
      if (t.organizationId === organizationId) {
        memoryThreats.delete(id);
        memoryRecommendations.delete(id);
      }
    }
    return;
  }

  await db
    .delete(incidentRecommendations)
    .where(eq(incidentRecommendations.organizationId, organizationId));

  return db
    .delete(threatDetections)
    .where(eq(threatDetections.organizationId, organizationId));
}

// Incident recommendations queries
export async function createIncidentRecommendation(data: InsertIncidentRecommendation) {
  const db = await getDb();
  if (!db) {
    const rec: IncidentRecommendation = {
      id: memoryRecIdCounter++,
      threatDetectionId: data.threatDetectionId,
      organizationId: data.organizationId,
      shortTermActions: (data.shortTermActions as any) || [],
      longTermActions: (data.longTermActions as any) || [],
      estimatedEffort: (data.estimatedEffort as any) || null,
      priority: (data.priority as any) || "high",
      aiGeneratedText: data.aiGeneratedText || null,
      status: (data.status as any) || "pending",
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    memoryRecommendations.set(rec.threatDetectionId, rec);
    return rec;
  }

  const result = await db.insert(incidentRecommendations).values(data).returning();
  return result[0];
}

export async function getRecommendationsByThreatId(threatDetectionId: number, organizationId?: number) {
  const db = await getDb();
  if (!db) {
    const rec = memoryRecommendations.get(threatDetectionId);
    if (!rec) return undefined;
    if (organizationId !== undefined && rec.organizationId !== organizationId) return undefined;
    return rec;
  }

  const conditions = organizationId !== undefined
    ? and(
        eq(incidentRecommendations.threatDetectionId, threatDetectionId),
        eq(incidentRecommendations.organizationId, organizationId)
      )
    : eq(incidentRecommendations.threatDetectionId, threatDetectionId);

  const result = await db
    .select()
    .from(incidentRecommendations)
    .where(conditions)
    .limit(1);

  return result.length > 0 ? result[0] : undefined;
}

// Incident reports queries
export async function createIncidentReport(data: InsertIncidentReport) {
  const db = await getDb();
  if (!db) {
    const rep: IncidentReport = {
      id: memoryReportIdCounter++,
      threatDetectionId: data.threatDetectionId || null,
      organizationId: data.organizationId,
      generatedBy: data.generatedBy || null,
      title: data.title || null,
      reportType: (data.reportType as any) || "combined",
      executiveSummary: data.executiveSummary || null,
      technicalAnalysis: data.technicalAnalysis || null,
      recommendations: data.recommendations || null,
      pdfUrl: data.pdfUrl || null,
      createdAt: new Date(),
    };
    memoryReports.set(rep.id, rep);
    return rep;
  }

  const result = await db.insert(incidentReports).values(data).returning();
  return result[0];
}

export async function getReportsByOrganization(
  organizationId: number,
  limit = 50,
  offset = 0
) {
  const db = await getDb();
  if (!db) {
    return Array.from(memoryReports.values())
      .filter((r) => r.organizationId === organizationId)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
      .slice(offset, offset + limit);
  }

  return await db
    .select()
    .from(incidentReports)
    .where(eq(incidentReports.organizationId, organizationId))
    .orderBy(desc(incidentReports.createdAt))
    .limit(limit)
    .offset(offset);
}

export async function getReportById(id: number, organizationId?: number) {
  const db = await getDb();
  if (!db) {
    const r = memoryReports.get(id);
    if (!r) return undefined;
    if (organizationId !== undefined && r.organizationId !== organizationId) return undefined;
    return r;
  }

  const conditions = organizationId !== undefined
    ? and(eq(incidentReports.id, id), eq(incidentReports.organizationId, organizationId))
    : eq(incidentReports.id, id);

  const result = await db
    .select()
    .from(incidentReports)
    .where(conditions)
    .limit(1);

  return result.length > 0 ? result[0] : undefined;
}

// Chat history queries
export async function createChatMessage(data: InsertChatHistoryRecord) {
  const db = await getDb();
  if (!db) {
    const msg: ChatHistoryRecord = {
      id: memoryChatIdCounter++,
      sessionId: data.sessionId || null,
      organizationId: data.organizationId,
      userId: data.userId || 1,
      userMessage: data.userMessage || null,
      aiResponse: data.aiResponse || null,
      context: data.context || null,
      createdAt: new Date(),
    };
    memoryChatHistory.push(msg);
    return msg;
  }

  const result = await db.insert(chatHistory).values(data).returning();
  return result[0];
}

export async function getChatHistory(
  sessionId: string,
  organizationId: number,
  limit = 50,
  offset = 0
) {
  const db = await getDb();
  if (!db) {
    return memoryChatHistory
      .filter((c) => c.sessionId === sessionId && c.organizationId === organizationId)
      .slice(-limit);
  }

  return await db
    .select()
    .from(chatHistory)
    .where(and(eq(chatHistory.sessionId, sessionId), eq(chatHistory.organizationId, organizationId)))
    .orderBy(desc(chatHistory.createdAt))
    .limit(limit)
    .offset(offset);
}

export async function createEndpoint(data: InsertEndpoint) {
  const db = await getDb();
  if (!db) {
    const epObj: Endpoint = {
      id: memoryEndpointIdCounter++,
      organizationId: data.organizationId,
      name: data.name,
      hostname: data.hostname || null,
      os: data.os || null,
      agentVersion: data.agentVersion || null,
      status: (data.status as any) || "pending",
      lastSeen: new Date(),
      enrolledAt: new Date(),
      revokedAt: null,
      createdAt: new Date(),
    };
    memoryEndpoints.set(epObj.id, epObj);
    return epObj;
  }

  const [created] = await db.insert(endpoints).values(data).returning();
  return created;
}

export async function listEndpointsByOrganization(organizationId: number) {
  const db = await getDb();
  if (!db) {
    return Array.from(memoryEndpoints.values())
      .filter((e) => e.organizationId === organizationId && e.status !== "revoked")
      .sort((a, b) => (b.lastSeen?.getTime() || 0) - (a.lastSeen?.getTime() || 0));
  }

  return await db
    .select()
    .from(endpoints)
    .where(eq(endpoints.organizationId, organizationId))
    .orderBy(desc(endpoints.lastSeen || endpoints.createdAt));
}

export async function getEndpointById(id: number) {
  const db = await getDb();
  if (!db) return memoryEndpoints.get(id);

  const result = await db.select().from(endpoints).where(eq(endpoints.id, id)).limit(1);
  return result[0];
}

export async function updateEndpointStatus(id: number, status: "pending" | "online" | "offline" | "warning" | "revoked") {
  const db = await getDb();
  if (!db) {
    const ep = memoryEndpoints.get(id);
    if (ep) {
      ep.status = status;
      ep.lastSeen = new Date();
    }
    return;
  }

  return await db
    .update(endpoints)
    .set({ status, lastSeen: new Date() })
    .where(eq(endpoints.id, id));
}

export async function revokeEndpoint(id: number, organizationId: number) {
  const db = await getDb();
  if (!db) {
    const ep = memoryEndpoints.get(id);
    if (ep && ep.organizationId === organizationId) {
      ep.status = "revoked";
      ep.revokedAt = new Date();
    }
    return;
  }

  return await db
    .update(endpoints)
    .set({ status: "revoked", revokedAt: new Date() })
    .where(and(eq(endpoints.id, id), eq(endpoints.organizationId, organizationId)));
}

export async function createEndpointEnrollmentToken(data: InsertEndpointEnrollmentToken) {
  const db = await getDb();
  if (!db) {
    const tok: EndpointEnrollmentToken = {
      id: memoryTokenIdCounter++,
      organizationId: data.organizationId,
      endpointId: data.endpointId || null,
      tokenHash: data.tokenHash,
      expiresAt: data.expiresAt,
      usedAt: null,
      revokedAt: null,
      createdAt: new Date(),
    };
    memoryTokens.set(tok.tokenHash, tok);
    return tok;
  }

  const result = await db.insert(endpointEnrollmentTokens).values(data).returning();
  return result[0];
}

export async function getValidEndpointEnrollmentToken(tokenHash: string) {
  const db = await getDb();
  if (!db) {
    const tok = memoryTokens.get(tokenHash);
    if (!tok || tok.revokedAt) return undefined;
    return tok;
  }

  const rows = await db
    .select()
    .from(endpointEnrollmentTokens)
    .where(and(eq(endpointEnrollmentTokens.tokenHash, tokenHash), isNull(endpointEnrollmentTokens.revokedAt)))
    .limit(1);

  return rows[0];
}

export async function invalidateEndpointEnrollmentToken(id: number) {
  const db = await getDb();
  if (!db) {
    for (const tok of Array.from(memoryTokens.values())) {
      if (tok.id === id) {
        tok.usedAt = new Date();
        tok.revokedAt = new Date();
      }
    }
    return;
  }

  return await db
    .update(endpointEnrollmentTokens)
    .set({ usedAt: new Date(), revokedAt: new Date() })
    .where(eq(endpointEnrollmentTokens.id, id));
}

export async function createEndpointCredential(data: InsertEndpointCredential) {
  const db = await getDb();
  if (!db) {
    const cred: EndpointCredential = {
      id: memoryCredIdCounter++,
      organizationId: data.organizationId,
      endpointId: data.endpointId,
      secretHash: data.secretHash,
      secretLabel: data.secretLabel || null,
      createdAt: new Date(),
      lastUsedAt: null,
      revokedAt: null,
    };
    memoryCredentials.set(cred.endpointId, cred);
    return cred;
  }

  const result = await db.insert(endpointCredentials).values(data).returning();
  return result[0];
}

export async function getEndpointCredentialByEndpointId(endpointId: number) {
  const db = await getDb();
  if (!db) {
    const cred = memoryCredentials.get(endpointId);
    if (!cred || cred.revokedAt) return undefined;
    return cred;
  }

  const result = await db
    .select()
    .from(endpointCredentials)
    .where(and(eq(endpointCredentials.endpointId, endpointId), isNull(endpointCredentials.revokedAt)))
    .limit(1);

  return result[0];
}

export async function createEndpointTelemetryRecord(data: InsertEndpointTelemetry) {
  const db = await getDb();
  if (!db) {
    const rec: EndpointTelemetry = {
      id: memoryTelemetryIdCounter++,
      organizationId: data.organizationId,
      endpointId: data.endpointId,
      eventType: data.eventType || "network_connection",
      sourceIp: data.sourceIp || null,
      destinationIp: data.destinationIp || null,
      protocol: data.protocol || "TCP",
      processName: data.processName || null,
      riskScore: String(data.riskScore || "0"),
      confidence: String(data.confidence || "0"),
      severity: (data.severity as any) || "low",
      eventData: data.eventData,
      createdAt: new Date(),
    };
    memoryTelemetry.unshift(rec);
    if (memoryTelemetry.length > 500) memoryTelemetry.pop();
    const ep = memoryEndpoints.get(data.endpointId);
    if (ep) {
      ep.lastSeen = new Date();
      if (Number(data.riskScore) >= 70 && ep.status !== "revoked") {
        ep.status = "warning";
      }
    }
    return rec;
  }

  const [created] = await db.insert(endpointTelemetry).values(data).returning();
  return created;
}

export async function getRecentTelemetryByEndpoint(endpointId: number, limit = 50) {
  const db = await getDb();
  if (!db) {
    return memoryTelemetry.filter((t) => t.endpointId === endpointId).slice(0, limit);
  }

  return await db
    .select()
    .from(endpointTelemetry)
    .where(eq(endpointTelemetry.endpointId, endpointId))
    .orderBy(desc(endpointTelemetry.createdAt))
    .limit(limit);
}

export async function getAllRecentTelemetry(organizationId: number, limit = 100) {
  const db = await getDb();
  if (!db) {
    return memoryTelemetry.filter((t) => t.organizationId === organizationId).slice(0, limit);
  }

  return await db
    .select()
    .from(endpointTelemetry)
    .where(eq(endpointTelemetry.organizationId, organizationId))
    .orderBy(desc(endpointTelemetry.createdAt))
    .limit(limit);
}

export async function deleteEndpoint(id: number, organizationId: number) {
  const db = await getDb();
  if (!db) {
    const ep = memoryEndpoints.get(id);
    if (ep && ep.organizationId === organizationId) {
      memoryEndpoints.delete(id);
    }
    return;
  }

  return await db
    .delete(endpoints)
    .where(and(eq(endpoints.id, id), eq(endpoints.organizationId, organizationId)));
}

// Dashboard metrics
export async function getDashboardMetrics(organizationId: number) {
  const db = await getDb();
  if (!db) {
    const threats = Array.from(memoryThreats.values()).filter((t) => t.organizationId === organizationId);
    const criticalThreats = threats.filter((t) => Number(t.riskScore) >= 80).length;
    const highThreats = threats.filter((t) => Number(t.riskScore) >= 60 && Number(t.riskScore) < 80).length;
    const mediumThreats = threats.filter((t) => Number(t.riskScore) >= 40 && Number(t.riskScore) < 60).length;
    const lowThreats = threats.filter((t) => Number(t.riskScore) < 40).length;

    let totalScore = 0;
    for (const t of threats) totalScore += Number(t.riskScore) || 0;
    const avgRiskScore = threats.length > 0 ? Math.round(totalScore / threats.length) : 0;

    return {
      eventsAnalyzed: Math.max(memoryTelemetry.length + memorySecurityLogs.size, 15),
      threatCount: threats.length,
      uniqueIncidents: threats.length,
      avgRiskScore,
      criticalThreats,
      highThreats,
      mediumThreats,
      lowThreats,
    };
  }

  const threatCount = await db
    .select({ count: sql<number>`COUNT(*)` })
    .from(threatDetections)
    .where(eq(threatDetections.organizationId, organizationId));

  const avgRiskScore = await db
    .select({ avg: sql<number>`AVG(${threatDetections.riskScore})` })
    .from(threatDetections)
    .where(eq(threatDetections.organizationId, organizationId));

  const criticalThreats = await db
    .select({ count: sql<number>`COUNT(*)` })
    .from(threatDetections)
    .where(
      and(
        eq(threatDetections.organizationId, organizationId),
        sql`${threatDetections.riskScore} >= 80`
      )
    );

  const severityCounts = await Promise.all(
    (["high", "medium", "low"] as const).map(async (severity) => {
      const result = await db
        .select({ count: sql<number>`COUNT(*)` })
        .from(threatDetections)
        .where(
          and(
            eq(threatDetections.organizationId, organizationId),
            sql`${threatDetections.riskScore} >= ${severity === "high" ? 60 : severity === "medium" ? 40 : 0}`,
            sql`${threatDetections.riskScore} < ${severity === "high" ? 80 : severity === "medium" ? 60 : 40}`
          )
        );
      return [severity, result[0]?.count || 0] as const;
    })
  );

  const eventsAnalyzed = await db
    .select({ count: sql<number>`COUNT(*)` })
    .from(securityLogs)
    .where(eq(securityLogs.organizationId, organizationId));

  return {
    eventsAnalyzed: eventsAnalyzed[0]?.count || 0,
    threatCount: threatCount[0]?.count || 0,
    uniqueIncidents: threatCount[0]?.count || 0,
    avgRiskScore: avgRiskScore[0]?.avg || 0,
    criticalThreats: criticalThreats[0]?.count || 0,
    highThreats: severityCounts.find(([severity]) => severity === "high")?.[1] || 0,
    mediumThreats: severityCounts.find(([severity]) => severity === "medium")?.[1] || 0,
    lowThreats: severityCounts.find(([severity]) => severity === "low")?.[1] || 0,
  };
}
