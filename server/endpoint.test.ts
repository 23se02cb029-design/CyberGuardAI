import { describe, expect, it } from "vitest";
import {
  analyzeEndpointTelemetry,
  calculateEndpointRiskScore,
  createEndpointEnrollmentToken,
  validateEndpointTelemetry,
} from "./services/securityEngine";

describe("endpoint monitoring", () => {
  it("creates a valid enrollment token for an authorized endpoint", () => {
    const token = createEndpointEnrollmentToken("OFFICE-PC-01", "acme-org");

    expect(token).toBeTruthy();
    expect(token).toMatch(/^endpoint_/);
    expect(token.length).toBeGreaterThan(24);
  });

  it("validates telemetry and rejects invalid payloads", () => {
    const invalid = {
      endpointId: "",
      timestamp: "not-a-date",
      eventType: "network_connection",
    };

    const result = validateEndpointTelemetry(invalid as any);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it("calculates a high risk score from repetitive suspicious endpoint behavior", () => {
    const events = [
      { endpointId: "ep-1", eventType: "network_connection", protocol: "TCP", destination: { ip: "203.0.113.42", port: 443 }, process: "browser.exe", confidence: 0.7 },
      { endpointId: "ep-1", eventType: "network_connection", protocol: "TCP", destination: { ip: "203.0.113.42", port: 443 }, process: "browser.exe", confidence: 0.8 },
      { endpointId: "ep-1", eventType: "network_connection", protocol: "TCP", destination: { ip: "203.0.113.42", port: 443 }, process: "browser.exe", confidence: 0.9 },
      { endpointId: "ep-1", eventType: "network_connection", protocol: "TCP", destination: { ip: "203.0.113.42", port: 22 }, process: "powershell.exe", confidence: 0.95 },
    ];

    const score = calculateEndpointRiskScore(events as any[]);
    expect(score).toBeGreaterThan(50);
  });

  it("detects suspicious endpoint activity with evidence and recommended follow-up", () => {
    const analysis = analyzeEndpointTelemetry({
      endpointId: "ep-1",
      eventType: "network_connection",
      protocol: "TCP",
      destination: { ip: "203.0.113.42", port: 22 },
      process: "powershell.exe",
      timestamp: new Date().toISOString(),
      bytesSent: 1000,
      bytesReceived: 2000,
      confidence: 0.94,
    } as any);

    expect(analysis.riskScore).toBeGreaterThan(0);
    expect(analysis.severity).toBeTruthy();
    expect(analysis.evidence.length).toBeGreaterThan(0);
    expect(analysis.recommendedInvestigation).toBeTruthy();
  });
});
