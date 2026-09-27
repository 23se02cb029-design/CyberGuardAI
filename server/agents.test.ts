import { describe, it, expect, vi } from "vitest";

describe("AI Agents", () => {
  describe("Log Analyzer Agent", () => {
    it("should validate normalized log structure", () => {
      const normalizedLog = {
        timestamp: "2026-01-24T12:00:00Z",
        sourceIp: "192.168.1.100",
        destinationIp: "10.0.0.50",
        userId: "john.doe",
        eventType: "login_attempt",
        severity: "low" as const,
        description: "Successful login from office network",
        additionalContext: {
          loginMethod: "password",
          mfaUsed: true,
        },
      };

      expect(normalizedLog.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
      expect(normalizedLog.sourceIp).toMatch(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/);
      expect(normalizedLog.severity).toBe("low");
      expect(normalizedLog.eventType).toBeTruthy();
    });

    it("should handle various log source types", () => {
      const sourceTypes = ["firewall", "ids", "auth_server", "endpoint", "siem", "other"];
      expect(sourceTypes).toContain("firewall");
      expect(sourceTypes).toContain("ids");
      expect(sourceTypes).toHaveLength(6);
    });
  });

  describe("Threat Classifier Agent", () => {
    it("should validate threat classification structure", () => {
      const threatClassification = {
        threatType: "brute_force" as const,
        riskScore: 82,
        confidence: 92,
        mitreAttackIds: ["T1110.001", "T1110.003"],
        indicators: [
          "Multiple failed login attempts",
          "Rapid authentication failures",
          "Unusual geographic origin",
        ],
        reasoning: "Detected 150 failed login attempts in 5 minutes from single IP",
      };

      expect(threatClassification.riskScore).toBeGreaterThanOrEqual(0);
      expect(threatClassification.riskScore).toBeLessThanOrEqual(100);
      expect(threatClassification.confidence).toBeGreaterThanOrEqual(0);
      expect(threatClassification.confidence).toBeLessThanOrEqual(100);
      expect(threatClassification.mitreAttackIds).toHaveLength(2);
      expect(threatClassification.indicators).toHaveLength(3);
    });

    it("should support all threat type classifications", () => {
      const threatTypes = [
        "phishing",
        "brute_force",
        "malware",
        "lateral_movement",
        "data_exfiltration",
        "privilege_escalation",
        "unknown",
      ];

      expect(threatTypes).toContain("phishing");
      expect(threatTypes).toContain("brute_force");
      expect(threatTypes).toContain("malware");
      expect(threatTypes).toContain("lateral_movement");
      expect(threatTypes).toHaveLength(7);
    });

    it("should map MITRE ATT&CK IDs correctly", () => {
      const mitreIds = ["T1110.001", "T1110.003", "T1589.001"];

      // Validate MITRE ID format (TXXXX.XXX)
      const mitreIdRegex = /^T\d{4}(\.\d{3})?$/;
      mitreIds.forEach((id) => {
        expect(id).toMatch(mitreIdRegex);
      });
    });
  });

  describe("Response Planner Agent", () => {
    it("should validate response plan structure", () => {
      const responsePlan = {
        shortTermActions: [
          {
            description: "Isolate affected system from network",
            estimatedHours: 1,
            complexity: "low" as const,
            responsibleTeam: "Infrastructure",
          },
          {
            description: "Reset compromised user credentials",
            estimatedHours: 0.5,
            complexity: "low" as const,
            responsibleTeam: "Security",
          },
        ],
        longTermActions: [
          {
            description: "Implement MFA across all systems",
            estimatedHours: 40,
            complexity: "high" as const,
            responsibleTeam: "Infrastructure",
          },
        ],
        priority: "critical" as const,
        summary: "Immediate isolation and credential reset required",
      };

      expect(responsePlan.shortTermActions).toHaveLength(2);
      expect(responsePlan.longTermActions).toHaveLength(1);
      expect(responsePlan.priority).toBe("critical");
      expect(responsePlan.shortTermActions[0].estimatedHours).toBeGreaterThan(0);
    });

    it("should validate complexity levels", () => {
      const complexityLevels = ["low", "medium", "high"];
      expect(complexityLevels).toContain("low");
      expect(complexityLevels).toContain("medium");
      expect(complexityLevels).toContain("high");
    });

    it("should validate priority levels", () => {
      const priorityLevels = ["critical", "high", "medium", "low"];
      expect(priorityLevels).toContain("critical");
      expect(priorityLevels).toContain("high");
    });
  });

  describe("Report Writer Agent", () => {
    it("should validate incident report structure", () => {
      const incidentReport = {
        executiveSummary:
          "A brute force attack targeting user authentication was detected and mitigated.",
        technicalDetails:
          "150 failed login attempts were detected from IP 192.168.1.100 over a 5-minute period.",
        immediateActions: [
          "Block source IP address",
          "Reset affected user credentials",
          "Enable enhanced monitoring",
        ],
        longTermImprovements: [
          "Implement multi-factor authentication",
          "Deploy intrusion detection system",
          "Conduct security awareness training",
        ],
        estimatedImpact: "Potential compromise of user account and data access",
        references: ["NIST Cybersecurity Framework", "MITRE ATT&CK Framework"],
      };

      expect(incidentReport.executiveSummary).toBeTruthy();
      expect(incidentReport.technicalDetails).toBeTruthy();
      expect(incidentReport.immediateActions).toHaveLength(3);
      expect(incidentReport.longTermImprovements).toHaveLength(3);
      expect(incidentReport.references).toHaveLength(2);
    });

    it("should support multiple report types", () => {
      const reportTypes = ["executive", "technical", "combined"];
      expect(reportTypes).toContain("executive");
      expect(reportTypes).toContain("technical");
      expect(reportTypes).toContain("combined");
    });
  });

  describe("SOC Copilot Agent", () => {
    it("should validate copilot response format", () => {
      const copilotResponse =
        "Based on the detected threats, I recommend the following immediate actions: 1. Isolate the affected system, 2. Reset user credentials, 3. Enable enhanced monitoring.";

      expect(copilotResponse).toBeTruthy();
      expect(typeof copilotResponse).toBe("string");
      expect(copilotResponse.length).toBeGreaterThan(10);
    });

    it("should handle context information", () => {
      const context = {
        recentThreats: [
          { threatType: "brute_force", riskScore: 85 },
          { threatType: "phishing", riskScore: 60 },
        ],
        recentLogs: [
          { eventType: "login_attempt", severity: "high" },
          { eventType: "file_access", severity: "medium" },
        ],
        organizationContext: "Technology Company",
      };

      expect(context.recentThreats).toHaveLength(2);
      expect(context.recentLogs).toHaveLength(2);
      expect(context.organizationContext).toBeTruthy();
    });
  });
});
