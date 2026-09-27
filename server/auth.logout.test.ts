import { describe, expect, it, vi } from "vitest";
import { appRouter } from "./routers";
import { COOKIE_NAME, REFRESH_COOKIE_NAME } from "../shared/const";
import type { TrpcContext } from "./_core/context";
import * as db from "./db";
import { hashPassword } from "./_core/password";
import { createSessionToken, verifySession } from "./_core/session";

type CookieCall = {
  name: string;
  options: Record<string, unknown>;
};

type AuthenticatedUser = NonNullable<TrpcContext["user"]>;

function createAuthContext(): { ctx: TrpcContext; clearedCookies: CookieCall[] } {
  const clearedCookies: CookieCall[] = [];

  const user: AuthenticatedUser = {
    id: 1,
    openId: "sample-user",
    email: "sample@example.com",
    name: "Sample User",
    loginMethod: "password",
    passwordHash: null,
    role: "user",
    createdAt: new Date(),
    updatedAt: new Date(),
    lastSignedIn: new Date(),
  };

  const ctx: TrpcContext = {
    user,
    req: {
      protocol: "https",
      headers: {},
    } as TrpcContext["req"],
    res: {
      clearCookie: (name: string, options: Record<string, unknown>) => {
        clearedCookies.push({ name, options });
      },
    } as TrpcContext["res"],
  };

  return { ctx, clearedCookies };
}

describe("auth.logout", () => {
  it("clears the session cookie and reports success", async () => {
    const { ctx, clearedCookies } = createAuthContext();
    const caller = appRouter.createCaller(ctx);

    const result = await caller.auth.logout();

    expect(result).toEqual({ success: true });
    expect(clearedCookies).toHaveLength(2);
    expect(clearedCookies.map(cookie => cookie.name)).toEqual(
      expect.arrayContaining([COOKIE_NAME, REFRESH_COOKIE_NAME])
    );
    expect(clearedCookies).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: COOKIE_NAME,
          options: expect.objectContaining({
            maxAge: -1,
            secure: true,
            sameSite: "lax",
            httpOnly: true,
            path: "/",
          }),
        }),
        expect.objectContaining({
          name: REFRESH_COOKIE_NAME,
          options: expect.objectContaining({
            maxAge: -1,
            secure: true,
            sameSite: "lax",
            httpOnly: true,
            path: "/",
          }),
        }),
      ])
    );
  });
});

describe("auth authorization", () => {
  it("rejects unauthenticated requests to auth.me", async () => {
    const caller = appRouter.createCaller({
      req: { protocol: "https", headers: {} } as TrpcContext["req"],
      res: {} as TrpcContext["res"],
      user: null,
    });

    await expect(caller.auth.me()).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it("accepts a valid session even when the user has no display name", async () => {
    const token = await createSessionToken("empty-name@example.com", { name: "" });
    await expect(verifySession(token)).resolves.toEqual({
      openId: "empty-name@example.com",
      name: "",
    });
  });

  it("allows a user without a display name to log in and authenticate", async () => {
    const user: AuthenticatedUser = {
      id: 12,
      openId: "no-name@example.com",
      email: "no-name@example.com",
      name: null,
      loginMethod: "password",
      passwordHash: await hashPassword("correct-password"),
      role: "user",
      organizationId: 1,
      createdAt: new Date(),
      updatedAt: new Date(),
      lastSignedIn: new Date(),
    };

    vi.spyOn(db, "getUserByOpenId").mockResolvedValue(user as any);
    vi.spyOn(db, "upsertUser").mockResolvedValue();

    const cookieJar: Record<string, string> = {};
    const caller = appRouter.createCaller({
      req: {
        protocol: "https",
        headers: {},
        ip: "127.0.0.1",
      } as TrpcContext["req"],
      res: {
        cookie: vi.fn((name: string, value: string) => {
          cookieJar[name] = value;
        }),
        clearCookie: vi.fn(),
      } as TrpcContext["res"],
      user: null,
    });

    const loginResult = await caller.auth.login({
      email: "no-name@example.com",
      password: "correct-password",
    });

    expect(loginResult.openId).toBe("no-name@example.com");
    expect(cookieJar[COOKIE_NAME]).toBeTruthy();

    const session = await verifySession(cookieJar[COOKIE_NAME]);
    expect(session).toEqual({
      openId: "no-name@example.com",
      name: "",
    });

    const meCaller = appRouter.createCaller({
      req: { protocol: "https", headers: {} } as TrpcContext["req"],
      res: {} as TrpcContext["res"],
      user: { ...user, name: null },
    });

    const me = await meCaller.auth.me();
    expect(me.openId).toBe("no-name@example.com");
    expect(me.name).toBeNull();
  });

  it("rejects non-admin users from admin-only routes", async () => {
    const user: AuthenticatedUser = {
      id: 2,
      openId: "user@example.com",
      email: "user@example.com",
      name: "Basic User",
      loginMethod: "password",
      passwordHash: null,
      role: "user",
      createdAt: new Date(),
      updatedAt: new Date(),
      lastSignedIn: new Date(),
    };

    const caller = appRouter.createCaller({
      req: { protocol: "https", headers: {} } as TrpcContext["req"],
      res: {} as TrpcContext["res"],
      user,
    });

    await expect(caller.threats.list({ limit: 10, offset: 0 })).rejects.toMatchObject({
      code: "FORBIDDEN",
    });
  });
});
