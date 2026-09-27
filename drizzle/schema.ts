import { decimal, integer, jsonb, pgEnum, pgTable, serial, text, timestamp, varchar } from "drizzle-orm/pg-core";

export const roleEnum = pgEnum("role", ["user", "admin"]);
export const threatTypeEnum = pgEnum("threat_type", [
  "phishing",
  "brute_force",
  "sql_injection",
  "path_traversal",
  "sensitive_file_access",
  "malware",
  "lateral_movement",
  "data_exfiltration",
  "privilege_escalation",
  "unknown",
]);
export const severityEnum = pgEnum("severity", ["low", "medium", "high", "critical"]);
export const threatStatusEnum = pgEnum("threat_status", [
  "new",
  "investigating",
  "confirmed",
  "false_positive",
  "resolved",
]);
export const priorityEnum = pgEnum("priority", ["critical", "high", "medium", "low"]);
export const recStatusEnum = pgEnum("rec_status", ["pending", "in_progress", "completed"]);
export const reportTypeEnum = pgEnum("report_type", ["executive", "technical", "combined"]);
export const endpointStatusEnum = pgEnum("endpoint_status", ["pending", "online", "offline", "warning", "revoked"]);

/**
 * Core user table backing auth flow.
 * Extend this file with additional tables as your product grows.
 * Columns use camelCase to match both database fields and generated types.
 */
export const users = pgTable("users", {
  /**
   * Surrogate primary key. Auto-incremented numeric value managed by the database.
   * Use this for relations between tables.
   */
  id: serial("id").primaryKey(),
  /** Unique login identifier. For password accounts this holds the lowercased email. */
  openId: varchar("openId", { length: 320 }).notNull().unique(),
  name: text("name"),
  email: varchar("email", { length: 320 }).unique(),
  loginMethod: varchar("loginMethod", { length: 64 }),
  passwordHash: text("passwordHash"),
  role: roleEnum("role").default("user").notNull(),
  organizationId: integer("organizationId"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().notNull().$onUpdate(() => new Date()),
  lastSignedIn: timestamp("lastSignedIn").defaultNow().notNull(),
});

export type User = typeof users.$inferSelect;
export type InsertUser = typeof users.$inferInsert;

export const passwordResetTokens = pgTable("password_reset_tokens", {
  id: serial("id").primaryKey(),
  userId: integer("userId").notNull().references(() => users.id, { onDelete: "cascade" }),
  tokenHash: varchar("tokenHash", { length: 128 }).notNull().unique(),
  expiresAt: timestamp("expiresAt").notNull(),
  usedAt: timestamp("usedAt"),
  revokedAt: timestamp("revokedAt"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type PasswordResetToken = typeof passwordResetTokens.$inferSelect;
export type InsertPasswordResetToken = typeof passwordResetTokens.$inferInsert;

// Organizations table for multi-tenant support
export const organizations = pgTable("organizations", {
  id: serial("id").primaryKey(),
  name: varchar("name", { length: 255 }).notNull(),
  ownerId: integer("ownerId").notNull(),
  industry: varchar("industry", { length: 100 }),
  maxLogsPerMonth: integer("maxLogsPerMonth").default(100000),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().notNull().$onUpdate(() => new Date()),
});

export type Organization = typeof organizations.$inferSelect;
export type InsertOrganization = typeof organizations.$inferInsert;

// Security logs table
export const securityLogs = pgTable("security_logs", {
  id: serial("id").primaryKey(),
  organizationId: integer("organizationId").notNull(),
  sourceType: varchar("sourceType", { length: 50 }),
  rawLog: text("rawLog"),
  normalizedLog: jsonb("normalizedLog"),
  timestamp: timestamp("timestamp"),
  sourceIp: varchar("sourceIp", { length: 45 }),
  destinationIp: varchar("destinationIp", { length: 45 }),
  userId: varchar("userId", { length: 255 }),
  eventType: varchar("eventType", { length: 100 }),
  severity: severityEnum("severity").default("low"),
  logHash: varchar("logHash", { length: 64 }).unique(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type SecurityLog = typeof securityLogs.$inferSelect;
export type InsertSecurityLog = typeof securityLogs.$inferInsert;

// Threat detections table
export const threatDetections = pgTable("threat_detections", {
  id: serial("id").primaryKey(),
  organizationId: integer("organizationId").notNull(),
  logId: integer("logId"),
  threatType: threatTypeEnum("threatType").default("unknown"),
  riskScore: decimal("riskScore", { precision: 5, scale: 2 }),
  confidence: decimal("confidence", { precision: 5, scale: 2 }),
  mitreAttackIds: jsonb("mitreAttackIds"),
  description: text("description"),
  indicators: jsonb("indicators"),
  affectedAssets: jsonb("affectedAssets"),
  aiAnalysis: text("aiAnalysis"),
  status: threatStatusEnum("status").default("new"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().notNull().$onUpdate(() => new Date()),
});

export type ThreatDetection = typeof threatDetections.$inferSelect;
export type InsertThreatDetection = typeof threatDetections.$inferInsert;

// Incident recommendations table
export const incidentRecommendations = pgTable("incident_recommendations", {
  id: serial("id").primaryKey(),
  threatDetectionId: integer("threatDetectionId").notNull(),
  organizationId: integer("organizationId").notNull(),
  shortTermActions: jsonb("shortTermActions"),
  longTermActions: jsonb("longTermActions"),
  estimatedEffort: jsonb("estimatedEffort"),
  priority: priorityEnum("priority").default("high"),
  aiGeneratedText: text("aiGeneratedText"),
  status: recStatusEnum("recStatus").default("pending"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().notNull().$onUpdate(() => new Date()),
});

export type IncidentRecommendation = typeof incidentRecommendations.$inferSelect;
export type InsertIncidentRecommendation = typeof incidentRecommendations.$inferInsert;

// Incident reports table
export const incidentReports = pgTable("incident_reports", {
  id: serial("id").primaryKey(),
  organizationId: integer("organizationId").notNull(),
  threatDetectionId: integer("threatDetectionId"),
  reportType: reportTypeEnum("reportType").default("combined"),
  title: varchar("title", { length: 255 }),
  executiveSummary: text("executiveSummary"),
  technicalAnalysis: text("technicalAnalysis"),
  recommendations: text("recommendations"),
  pdfUrl: varchar("pdfUrl", { length: 500 }),
  generatedBy: integer("generatedBy"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type IncidentReport = typeof incidentReports.$inferSelect;
export type InsertIncidentReport = typeof incidentReports.$inferInsert;

// Chat history table
export const chatHistory = pgTable("chat_history", {
  id: serial("id").primaryKey(),
  organizationId: integer("organizationId").notNull(),
  userId: integer("userId").notNull(),
  sessionId: varchar("sessionId", { length: 64 }),
  userMessage: text("userMessage"),
  aiResponse: text("aiResponse"),
  context: jsonb("context"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type ChatHistoryRecord = typeof chatHistory.$inferSelect;
export type InsertChatHistoryRecord = typeof chatHistory.$inferInsert;

export const endpoints = pgTable("endpoints", {
  id: serial("id").primaryKey(),
  organizationId: integer("organizationId").notNull(),
  name: varchar("name", { length: 255 }).notNull(),
  hostname: varchar("hostname", { length: 255 }),
  os: varchar("os", { length: 100 }),
  agentVersion: varchar("agentVersion", { length: 60 }),
  status: endpointStatusEnum("status").default("pending").notNull(),
  lastSeen: timestamp("lastSeen"),
  enrolledAt: timestamp("enrolledAt").defaultNow().notNull(),
  revokedAt: timestamp("revokedAt"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type Endpoint = typeof endpoints.$inferSelect;
export type InsertEndpoint = typeof endpoints.$inferInsert;

export const endpointEnrollmentTokens = pgTable("endpoint_enrollment_tokens", {
  id: serial("id").primaryKey(),
  organizationId: integer("organizationId").notNull(),
  endpointId: integer("endpointId"),
  tokenHash: varchar("tokenHash", { length: 128 }).notNull().unique(),
  expiresAt: timestamp("expiresAt").notNull(),
  usedAt: timestamp("usedAt"),
  revokedAt: timestamp("revokedAt"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type EndpointEnrollmentToken = typeof endpointEnrollmentTokens.$inferSelect;
export type InsertEndpointEnrollmentToken = typeof endpointEnrollmentTokens.$inferInsert;

export const endpointCredentials = pgTable("endpoint_credentials", {
  id: serial("id").primaryKey(),
  organizationId: integer("organizationId").notNull(),
  endpointId: integer("endpointId").notNull(),
  secretHash: varchar("secretHash", { length: 128 }).notNull(),
  secretLabel: varchar("secretLabel", { length: 120 }),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  lastUsedAt: timestamp("lastUsedAt"),
  revokedAt: timestamp("revokedAt"),
});

export type EndpointCredential = typeof endpointCredentials.$inferSelect;
export type InsertEndpointCredential = typeof endpointCredentials.$inferInsert;

export const endpointTelemetry = pgTable("endpoint_telemetry", {
  id: serial("id").primaryKey(),
  organizationId: integer("organizationId").notNull(),
  endpointId: integer("endpointId").notNull(),
  eventType: varchar("eventType", { length: 80 }).default("network_connection").notNull(),
  sourceIp: varchar("sourceIp", { length: 45 }),
  destinationIp: varchar("destinationIp", { length: 45 }),
  protocol: varchar("protocol", { length: 20 }),
  processName: varchar("processName", { length: 200 }),
  riskScore: decimal("riskScore", { precision: 5, scale: 2 }).default("0"),
  confidence: decimal("confidence", { precision: 5, scale: 2 }).default("0"),
  severity: severityEnum("severity").default("low"),
  eventData: jsonb("eventData").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type EndpointTelemetry = typeof endpointTelemetry.$inferSelect;
export type InsertEndpointTelemetry = typeof endpointTelemetry.$inferInsert;
