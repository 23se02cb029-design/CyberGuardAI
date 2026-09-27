import { describe, expect, it } from "vitest";
import { analyzeWithHeuristics } from "./services/securityEngine";

describe("securityEngine heuristics", () => {
  it("detects SQL injection payloads from raw log text", () => {
    const log = `
      2026-09-18T10:00:00Z app[123]: WARN SQL query="SELECT * FROM users WHERE username='admin' OR '1'='1'" source=10.0.0.5
      2026-09-18T10:00:01Z app[123]: WARN sql_error="DB error: syntax error near 'OR'"
    `;

    const analysis = analyzeWithHeuristics(log);

    expect(analysis.riskScore).toBeGreaterThan(40);
    expect(analysis.vulnerabilities.some((v) => /sql injection/i.test(v))).toBe(true);
    expect(analysis.detections.some((d) => d.threatType === "sql_injection")).toBe(true);
  });

  it("detects XSS payloads and marks them as suspicious activity", () => {
    const log = `
      2026-09-18T10:10:00Z web[321]: WARN request="GET /search?q=<script>alert('x')</script>" status=200
      2026-09-18T10:10:03Z web[321]: WARN html="<img src=x onerror=alert(1)>"
    `;

    const analysis = analyzeWithHeuristics(log);

    expect(analysis.vulnerabilities.some((v) => /xss|cross-site scripting|script/i.test(v))).toBe(true);
    expect(analysis.riskScore).toBeGreaterThan(30);
  });

  it("detects path traversal attempts and sensitive file access", () => {
    const log = `
      2026-09-18T11:00:00Z web[500]: WARN request="GET /../../etc/passwd HTTP/1.1" status=400
      2026-09-18T11:00:02Z web[500]: WARN file="/etc/shadow" action=READ user=admin
    `;

    const analysis = analyzeWithHeuristics(log);
    const threatTypes = analysis.detections.map((d) => d.threatType);

    expect(threatTypes).toContain("path_traversal");
    expect(threatTypes).toContain("sensitive_file_access");
  });

  it("detects repeated failed logins as brute force", () => {
    const log = `
      2026-09-18T12:00:00Z auth[55]: WARN SourceIP=203.0.113.10 User=admin Action=LOGIN Status=FAILED
      2026-09-18T12:00:10Z auth[55]: WARN SourceIP=203.0.113.10 User=admin Action=LOGIN Status=FAILED
      2026-09-18T12:00:20Z auth[55]: WARN SourceIP=203.0.113.10 User=admin Action=LOGIN Status=FAILED
      2026-09-18T12:00:30Z auth[55]: WARN SourceIP=203.0.113.10 User=admin Action=LOGIN Status=FAILED
      2026-09-18T12:00:40Z auth[55]: WARN SourceIP=203.0.113.10 User=admin Action=LOGIN Status=SUCCESS
    `;

    const analysis = analyzeWithHeuristics(log);

    expect(analysis.detections.some((d) => d.threatType === "brute_force")).toBe(true);
    expect(analysis.riskScore).toBeGreaterThan(50);
  });

  it("does not flag normal, low-risk traffic as suspicious", () => {
    const log = `
      2026-09-18T13:00:00Z firewall[10]: INFO src=10.0.0.5 dst=10.0.0.10 proto=tcp sport=49152 dport=443 action=ALLOW bytes=1024
      2026-09-18T13:00:01Z firewall[10]: INFO src=10.0.0.5 dst=10.0.0.10 proto=tcp sport=49153 dport=443 action=ALLOW bytes=1024
    `;

    const analysis = analyzeWithHeuristics(log);

    expect(analysis.detections).toHaveLength(0);
    expect(analysis.riskScore).toBe(0);
    expect(analysis.reasoning).toContain("NO THREAT DETECTED");
  });

  it("does not false-positive on safe authentication events", () => {
    const log = `
      2026-09-18T14:00:00Z auth[7]: INFO User=alice SourceIP=10.0.0.12 Action=LOGIN Status=SUCCESS
      2026-09-18T14:02:00Z auth[7]: INFO User=alice SourceIP=10.0.0.12 Action=LOGOUT Status=SUCCESS
    `;

    const analysis = analyzeWithHeuristics(log);

    expect(analysis.detections).toHaveLength(0);
  });
});
