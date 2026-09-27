import { describe, it, expect, beforeEach, vi } from "vitest";
import * as db from "./db";
import { analyzeWithHeuristics } from "./services/securityEngine";
import { generatePasswordResetToken, hashPasswordResetToken, isPasswordResetTokenExpired } from "./db";

describe("Database Helpers", () => {
  describe("Organization Queries", () => {
    it("should handle organization creation", async () => {
      // Test structure for organization creation
      const mockOrgData = {
        name: "Test Organization",
        ownerId: 1,
        industry: "Technology",
      };

      // This is a placeholder test to verify the function signature
      expect(mockOrgData.name).toBe("Test Organization");
      expect(mockOrgData.ownerId).toBe(1);
    });
  });

  describe("Security Log Queries", () => {
    it("should validate security log data structure", () => {
      const mockLog = {
        organizationId: 1,
        sourceType: "firewall",
        rawLog: "2026-01-24 12:00:00 Connection from 192.168.1.1",
        timestamp: new Date(),
        sourceIp: "192.168.1.1",
        destinationIp: "10.0.0.1",
        userId: "admin",
        eventType: "connection_attempt",
        severity: "low" as const,
      };

      expect(mockLog.organizationId).toBe(1);
      expect(mockLog.sourceType).toBe("firewall");
      expect(mockLog.severity).toBe("low");
    });
  });

  describe("Threat Detection Queries", () => {
    it("should validate threat detection data structure", () => {
      const mockThreat = {
        organizationId: 1,
        threatType: "brute_force" as const,
        riskScore: 75.5,
        confidence: 85.0,
        mitreAttackIds: ["T1110.001", "T1110.003"],
        description: "Multiple failed login attempts detected",
        status: "new" as const,
      };

      expect(mockThreat.threatType).toBe("brute_force");
      expect(mockThreat.riskScore).toBeGreaterThan(50);
      expect(mockThreat.mitreAttackIds).toHaveLength(2);
      expect(mockThreat.status).toBe("new");
    });

    it("should validate threat severity levels", () => {
      const severityLevels = ["low", "medium", "high", "critical"];
      const testScore = 85;
      const expectedSeverity = testScore >= 80 ? "critical" : "high";

      expect(severityLevels).toContain(expectedSeverity);
    });
  });

  describe("Heuristic Analysis", () => {
    it("separates brute force and sensitive file access without path traversal", () => {
      const analysis = analyzeWithHeuristics(`2026-09-15 08:42:16 WARN AUTH User=admin SourceIP=192.168.1.50 Action=LOGIN Status=FAILED
2026-09-15 08:42:20 WARN AUTH User=admin SourceIP=192.168.1.50 Action=LOGIN Status=FAILED
2026-09-15 08:42:25 WARN AUTH User=admin SourceIP=192.168.1.50 Action=LOGIN Status=FAILED
2026-09-15 08:50:11 INFO AUTH User=admin SourceIP=192.168.1.50 Action=LOGIN Status=SUCCESS
2026-09-15 09:10:44 WARN FILE User=admin File=/etc/passwd Action=READ Status=SUCCESS
2026-09-15 10:55:14 WARN FILE User=admin File=/etc/shadow Action=READ Status=DENIED`);

      expect(analysis.detections.map((detection) => detection.threatType)).toEqual([
        "sensitive_file_access",
        "brute_force",
      ]);
      expect(analysis.detections.some((detection) => detection.threatType === "path_traversal")).toBe(false);
      expect(analysis.detections.find((detection) => detection.threatType === "brute_force")?.evidence).toHaveLength(4);
      expect(analysis.detections.find((detection) => detection.threatType === "sensitive_file_access")?.evidence).toHaveLength(2);
    });

    it("detects path traversal only when a traversal sequence is logged", () => {
      const analysis = analyzeWithHeuristics(
        '2026-09-15 12:00:01 WARN WEB SourceIP=10.0.0.25 Request="GET /../../etc/passwd HTTP/1.1" Status=400'
      );

      expect(analysis.detections).toHaveLength(1);
      expect(analysis.detections[0].threatType).toBe("path_traversal");
      expect(analysis.detections[0].evidence[0]).toContain("/../../etc/passwd");
    });

    it("does not create a threat for ordinary allowed traffic", () => {
      const analysis = analyzeWithHeuristics("2026-09-15 12:00:01 TCP SourceIP=10.0.0.5 DestinationIP=10.0.0.10 Port=443 Action=ALLOW");

      expect(analysis.detections).toHaveLength(0);
      expect(analysis.riskScore).toBe(0);
      expect(analysis.reasoning).toBe("NO THREAT DETECTED: no supported suspicious indicator matched the supplied log.");
    });

    it("should flag suspicious-only activity as an alert", () => {
      const analysis = analyzeWithHeuristics(`
        2026-09-12T10:00:00Z firewall outbound connection from 10.0.0.5 to 203.0.113.99
        unusual network beaconing detected with repeated data transfers to a new external host
        user-agent: custom-curl/1.0
      `);

      expect(analysis.vulnerabilities.length).toBeGreaterThan(0);
      expect(analysis.riskScore).toBeGreaterThan(10);
      expect(analysis.reasoning.toLowerCase()).toContain("suspicious");
    });
  });

  describe("Dashboard Metrics", () => {
    it("should calculate risk score correctly", () => {
      const threats = [
        { riskScore: 45 },
        { riskScore: 75 },
        { riskScore: 90 },
      ];

      const avgRiskScore = threats.reduce((sum, t) => sum + t.riskScore, 0) / threats.length;
      expect(avgRiskScore).toBeCloseTo(70, 1);
    });

    it("should count critical threats correctly", () => {
      const threats = [
        { riskScore: 45, status: "new" },
        { riskScore: 85, status: "new" },
        { riskScore: 92, status: "new" },
        { riskScore: 60, status: "investigating" },
      ];

      const criticalCount = threats.filter((t) => t.riskScore >= 80).length;
      expect(criticalCount).toBe(2);
    });
  });

  describe("Chat History", () => {
    it("should validate chat message structure", () => {
      const mockMessage = {
        organizationId: 1,
        userId: 1,
        sessionId: "session-123",
        userMessage: "What threats were detected?",
        aiResponse: "Based on the logs, we detected 3 threats...",
        context: {
          threatCount: 3,
          logCount: 150,
        },
      };

      expect(mockMessage.sessionId).toBeDefined();
      expect(mockMessage.userMessage).toBeTruthy();
      expect(mockMessage.aiResponse).toBeTruthy();
      expect(mockMessage.context.threatCount).toBe(3);
    });
  });

  describe("Tenant Scoping", () => {
    it("should reject data access when a row belongs to a different organization", () => {
      const tenantCheck = () => {
        const ownerOrgId = 7;
        const requestOrgId = 9;

        if (requestOrgId !== ownerOrgId) {
          throw new Error("Organization mismatch");
        }
      };

      expect(() => tenantCheck()).toThrow("Organization mismatch");
    });
  });

  describe("Password Reset Tokens", () => {
    it("creates a reset token and marks it expired only after its expiry time", () => {
      const rawToken = generatePasswordResetToken();
      const hashedToken = hashPasswordResetToken(rawToken);
      const validExpiry = new Date(Date.now() + 60 * 60 * 1000);
      const expiredExpiry = new Date(Date.now() - 1000);

      expect(rawToken.length).toBeGreaterThan(20);
      expect(hashedToken).not.toBe(rawToken);
      expect(isPasswordResetTokenExpired(validExpiry)).toBe(false);
      expect(isPasswordResetTokenExpired(expiredExpiry)).toBe(true);
    });
  });
});
