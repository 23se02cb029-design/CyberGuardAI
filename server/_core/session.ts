import crypto from "crypto";
import { ACCESS_TOKEN_MS, COOKIE_NAME, REFRESH_COOKIE_NAME, REFRESH_TOKEN_MS } from "@shared/const";
import { ForbiddenError } from "@shared/_core/errors";
import { parse as parseCookieHeader } from "cookie";
import type { Request } from "express";
import { SignJWT, jwtVerify } from "jose";
import type { User } from "../../drizzle/schema";
import * as db from "../db";
import { ENV } from "./env";

const isNonEmptyString = (value: unknown): value is string =>
  typeof value === "string" && value.length > 0;

export type SessionPayload = {
  openId: string;
  name: string;
};

export const refreshTokens = new Map<string, { userOpenId: string; expiresAt: number }>();

export function hashRefreshToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

export function createRefreshToken(openId: string): string {
  const token = `rt_${crypto.randomBytes(32).toString("hex")}`;
  refreshTokens.set(hashRefreshToken(token), {
    userOpenId: openId,
    expiresAt: Date.now() + REFRESH_TOKEN_MS,
  });
  return token;
}

export function consumeRefreshToken(token: string): { userOpenId: string } | null {
  const hash = hashRefreshToken(token);
  const current = refreshTokens.get(hash);

  if (!current) return null;
  if (current.expiresAt < Date.now()) {
    refreshTokens.delete(hash);
    return null;
  }

  refreshTokens.delete(hash);
  return { userOpenId: current.userOpenId };
}

export function revokeRefreshToken(token: string | undefined | null): void {
  if (!token) return;
  refreshTokens.delete(hashRefreshToken(token));
}

export function revokeAllRefreshTokensForUser(userOpenId: string): void {
  for (const [hash, entry] of Array.from(refreshTokens.entries())) {
    if (entry.userOpenId === userOpenId) {
      refreshTokens.delete(hash);
    }
  }
}

function parseCookies(cookieHeader: string | undefined) {
  if (!cookieHeader) {
    return new Map<string, string>();
  }

  const parsed = parseCookieHeader(cookieHeader);
  return new Map(Object.entries(parsed));
}

function getSessionSecret() {
  return new TextEncoder().encode(ENV.cookieSecret);
}

export async function createSessionToken(
  openId: string,
  options: { expiresInMs?: number; name?: string } = {}
): Promise<string> {
  return signSession(
    { openId, name: options.name || "" },
    { expiresInMs: options.expiresInMs ?? ACCESS_TOKEN_MS }
  );
}

export async function signSession(
  payload: SessionPayload,
  options: { expiresInMs?: number } = {}
): Promise<string> {
  const issuedAt = Date.now();
  const expiresInMs = options.expiresInMs ?? ACCESS_TOKEN_MS;
  const expirationSeconds = Math.floor((issuedAt + expiresInMs) / 1000);
  const secretKey = getSessionSecret();

  return new SignJWT({
    openId: payload.openId,
    name: payload.name,
  })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setExpirationTime(expirationSeconds)
    .sign(secretKey);
}

export async function verifySession(
  cookieValue: string | undefined | null
): Promise<{ openId: string; name: string } | null> {
  if (!cookieValue) {
    return null;
  }

  try {
    const secretKey = getSessionSecret();
    const { payload } = await jwtVerify(cookieValue, secretKey, {
      algorithms: ["HS256"],
    });
    const { openId, name } = payload as Record<string, unknown>;

    if (!isNonEmptyString(openId)) {
      console.warn("[Auth] Session payload missing required user identifier");
      return null;
    }

    return {
      openId,
      name: typeof name === "string" ? name : "",
    };
  } catch (error) {
    console.warn("[Auth] Session verification failed", String(error));
    return null;
  }
}

export async function authenticateRequest(req: Request): Promise<User> {
  const cookies = parseCookies(req.headers.cookie);
  const sessionCookie = cookies.get(COOKIE_NAME);
  const session = await verifySession(sessionCookie);

  if (!session) {
    throw ForbiddenError("Invalid session cookie");
  }

  let user: User | undefined;
  try {
    user = await db.getUserByOpenId(session.openId);
  } catch (error) {
    // If the database is unreachable, throw the real error instead of
    // masking it as "User not found" (which causes redirect loops).
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[Auth] Database error during authentication: ${message}`);
    throw error;
  }

  if (!user) {
    throw ForbiddenError("User not found");
  }

  if (!user.organizationId) {
    let organization = await db.getOrganizationByOwnerId(user.id);
    if (!organization) {
      organization = await db.createOrganization(
        `${user.name || user.email || "CyberGuard"} SOC`,
        user.id,
        "Cybersecurity"
      );
    }
    await db.upsertUser({
      openId: user.openId,
      organizationId: organization.id,
      lastSignedIn: new Date(),
    });
    const refreshed = await db.getUserByOpenId(user.openId);
    return refreshed || { ...user, organizationId: organization.id };
  }

  await db.upsertUser({
    openId: user.openId,
    lastSignedIn: new Date(),
  });

  return user;
}
