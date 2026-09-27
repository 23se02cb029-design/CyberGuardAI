import { beforeEach, describe, expect, it, vi } from "vitest";
import * as db from "./db";
import { clearRateLimit } from "./_core/rateLimit";
import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";

function makeCaller(user?: TrpcContext["user"], ip = "127.0.0.1") {
  return appRouter.createCaller({
    user: user ?? null,
    req: {
      protocol: "https",
      headers: {
        host: "localhost",
        "x-forwarded-proto": "https",
      },
      ip,
    } as TrpcContext["req"],
    res: {
      cookie: vi.fn(),
      clearCookie: vi.fn(),
    } as TrpcContext["res"],
  });
}

describe("password reset workflow", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    process.env.NODE_ENV = "development";
    clearRateLimit("ip:127.0.0.1");
    clearRateLimit("ip:127.0.0.2");
    clearRateLimit("ip:127.0.0.3");
    clearRateLimit("acct:user@example.com");
    clearRateLimit("acct:limit@example.com");
    clearRateLimit("acct:prod@example.com");
    clearRateLimit("acct:repeat@example.com");
    clearRateLimit("acct:expired@example.com");
    clearRateLimit("acct:missing@example.com");
  });

  it("creates a reset token for a registered user and stores it securely", async () => {
    const user = {
      id: 42,
      openId: "user@example.com",
      email: "User@Example.com",
      name: "User Example",
      loginMethod: "password",
      passwordHash: "hash",
      role: "user",
      organizationId: 1,
      createdAt: new Date(),
      updatedAt: new Date(),
      lastSignedIn: new Date(),
    } as const;

    vi.spyOn(db, "getUserByOpenId").mockResolvedValue(user as any);
    vi.spyOn(db, "getDb").mockResolvedValue(null as any);

    const result = await makeCaller().auth.forgotPassword({ email: "User@Example.com" });

    expect(result.success).toBe(true);
    expect(result.message).toMatch(/reset/i);
    if (result.resetToken) {
      expect(result.resetToken).toMatch(/^pwreset_/);
      expect(result.resetToken).not.toContain("user@example.com");
    }

    const stored = await db.getPasswordResetTokenForUser("user@example.com");
    expect(stored).toBeTruthy();
    expect(stored?.tokenHash).toBeTruthy();
    expect(stored?.expiresAt.getTime()).toBeGreaterThan(Date.now());
  });

  it("returns a safe generic message for an unknown email", async () => {
    vi.spyOn(db, "getUserByOpenId").mockResolvedValue(undefined);
    vi.spyOn(db, "getDb").mockResolvedValue(null as any);

    const result = await makeCaller().auth.forgotPassword({ email: "missing@example.com" });

    expect(result.success).toBe(true);
    expect(result.message).toMatch(/if an account exists|reset link/i);
    expect(result.resetToken).toBeUndefined();
  });

  it("accepts a valid reset token and resets the password", async () => {
    const user = {
      id: 99,
      openId: "user@example.com",
      email: "user@example.com",
      name: "User Example",
      loginMethod: "password",
      passwordHash: "oldHash",
      role: "user",
      organizationId: 1,
      createdAt: new Date(),
      updatedAt: new Date(),
      lastSignedIn: new Date(),
    } as const;

    const token = db.generatePasswordResetToken();
    await db.storePasswordResetToken({
      userOpenId: user.openId,
      userId: user.id,
      token,
      expiresAt: Date.now() + 1000 * 60 * 15,
    });

    vi.spyOn(db, "getUserByOpenId").mockResolvedValue(user as any);
    vi.spyOn(db, "upsertUser").mockResolvedValue();

    const result = await makeCaller().auth.resetPassword({
      email: "user@example.com",
      token,
      password: "newPassword123",
    });

    expect(result.success).toBe(true);
    expect(result.message).toMatch(/Password updated/i);
  });

  it("rejects expired reset tokens", async () => {
    const user = {
      id: 7,
      openId: "expired@example.com",
      email: "expired@example.com",
      name: "Expired User",
      loginMethod: "password",
      passwordHash: "hash",
      role: "user",
      organizationId: 1,
      createdAt: new Date(),
      updatedAt: new Date(),
      lastSignedIn: new Date(),
    } as const;

    const token = db.generatePasswordResetToken();
    await db.storePasswordResetToken({
      userOpenId: user.openId,
      userId: user.id,
      token,
      expiresAt: Date.now() - 1000,
    });

    vi.spyOn(db, "getUserByOpenId").mockResolvedValue(user as any);

    await expect(
      makeCaller().auth.resetPassword({
        email: user.email,
        token,
        password: "newPassword456",
      })
    ).rejects.toMatchObject({ code: "UNAUTHORIZED" });
  });

  it("rejects a reused reset token after a successful reset", async () => {
    const user = {
      id: 5,
      openId: "repeat@example.com",
      email: "repeat@example.com",
      name: "Repeat User",
      loginMethod: "password",
      passwordHash: "hash",
      role: "user",
      organizationId: 1,
      createdAt: new Date(),
      updatedAt: new Date(),
      lastSignedIn: new Date(),
    } as const;

    const token = db.generatePasswordResetToken();
    await db.storePasswordResetToken({
      userOpenId: user.openId,
      userId: user.id,
      token,
      expiresAt: Date.now() + 1000 * 60 * 15,
    });

    vi.spyOn(db, "getUserByOpenId").mockResolvedValue(user as any);
    vi.spyOn(db, "upsertUser").mockResolvedValue();

    await makeCaller().auth.resetPassword({
      email: user.email,
      token,
      password: "newPassword789",
    });

    await expect(
      makeCaller().auth.resetPassword({
        email: user.email,
        token,
        password: "anotherPassword123",
      })
    ).rejects.toMatchObject({ code: "UNAUTHORIZED" });
  });

  it("blocks excessive reset attempts with the rate limiter", async () => {
    const user = {
      id: 11,
      openId: "limit@example.com",
      email: "limit@example.com",
      name: "Limit User",
      loginMethod: "password",
      passwordHash: "hash",
      role: "user",
      organizationId: 1,
      createdAt: new Date(),
      updatedAt: new Date(),
      lastSignedIn: new Date(),
    } as const;

    vi.spyOn(db, "getUserByOpenId").mockResolvedValue(user as any);
    vi.spyOn(db, "getDb").mockResolvedValue(null as any);

    const caller = makeCaller();
    await caller.auth.forgotPassword({ email: user.email });
    await caller.auth.forgotPassword({ email: user.email });
    await caller.auth.forgotPassword({ email: user.email });

    await expect(caller.auth.forgotPassword({ email: user.email })).rejects.toMatchObject({
      code: "TOO_MANY_REQUESTS",
    });
  });

  it("does not expose the raw reset token in production responses", async () => {
    process.env.NODE_ENV = "production";
    const user = {
      id: 82,
      openId: "prod@example.com",
      email: "prod@example.com",
      name: "Prod User",
      loginMethod: "password",
      passwordHash: "hash",
      role: "user",
      organizationId: 1,
      createdAt: new Date(),
      updatedAt: new Date(),
      lastSignedIn: new Date(),
    } as const;

    vi.spyOn(db, "getUserByOpenId").mockResolvedValue(user as any);
    vi.spyOn(db, "getDb").mockResolvedValue(null as any);

    const result = await makeCaller().auth.forgotPassword({ email: user.email });

    expect(result.success).toBe(true);
    expect(result.resetToken).toBeUndefined();
    expect(result.message).toMatch(/reset link|reset request/i);
  });
});
