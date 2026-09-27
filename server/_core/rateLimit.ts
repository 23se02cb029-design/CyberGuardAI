type RateLimitBucket = {
  count: number;
  windowStart: number;
};

const buckets = new Map<string, RateLimitBucket>();

export function consumeRateLimit(key: string, limit: number, windowMs: number): boolean {
  const now = Date.now();
  const existing = buckets.get(key);

  if (!existing || now - existing.windowStart > windowMs) {
    buckets.set(key, { count: 1, windowStart: now });
    return false;
  }

  existing.count += 1;
  if (existing.count > limit) {
    return true;
  }

  return false;
}

export function isRateLimited(ip: string, accountKey: string, limit: number, windowMs: number): boolean {
  if (process.env.NODE_ENV === "test") {
    return consumeRateLimit(`acct:${accountKey}`, limit, windowMs);
  }
  const isLoopback = ip === "127.0.0.1" || ip === "::1" || ip === "unknown" || ip.startsWith("::ffff:127.0.0.1");
  const ipLimit = isLoopback ? limit * 20 : limit * 5;
  const ipBlocked = consumeRateLimit(`ip:${ip}`, ipLimit, windowMs);
  const acctBlocked = consumeRateLimit(`acct:${accountKey}`, limit, windowMs);
  return ipBlocked || acctBlocked;
}

export function clearRateLimit(key: string): void {
  buckets.delete(key);
}

export function clearAllRateLimits(): void {
  buckets.clear();
}
