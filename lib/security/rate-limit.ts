import net from "node:net";

type Bucket = { count: number; resetAt: number };

const WINDOW_MS = 60_000;
const MAX_PER_WINDOW = 12;
const MAX_BUCKETS = 10_000;
const OVERFLOW_KEY = "__overflow__";

const buckets = new Map<string, Bucket>([[OVERFLOW_KEY, { count: 0, resetAt: 0 }]]);

function pruneExpired(now: number): void {
  if (buckets.size < MAX_BUCKETS) return;
  for (const [key, bucket] of buckets) {
    if (key !== OVERFLOW_KEY && bucket.resetAt <= now) buckets.delete(key);
  }
}

export function rateLimit(key: string): { ok: true } | { ok: false; retryAfterSec: number } {
  const now = Date.now();
  pruneExpired(now);
  const effectiveKey = buckets.has(key) || buckets.size < MAX_BUCKETS ? key : OVERFLOW_KEY;
  const bucket = buckets.get(effectiveKey);
  if (!bucket || bucket.resetAt <= now) {
    buckets.set(effectiveKey, { count: 1, resetAt: now + WINDOW_MS });
    return { ok: true };
  }
  if (bucket.count >= MAX_PER_WINDOW) {
    return { ok: false, retryAfterSec: Math.ceil((bucket.resetAt - now) / 1000) };
  }
  bucket.count += 1;
  return { ok: true };
}

function firstValidIp(value: string | null): string | null {
  if (!value) return null;
  for (const candidate of value.split(",")) {
    const address = candidate.trim();
    if (net.isIP(address) !== 0) return address;
  }
  return null;
}

export function clientKeyFromHeaders(headers: Headers): string {
  // Vercel preserves its own copy even when an upstream proxy rewrites XFF.
  // Fall back for local/self-hosted deployments, but never accept arbitrary
  // strings as map keys.
  return (
    firstValidIp(headers.get("x-vercel-forwarded-for")) ??
    firstValidIp(headers.get("x-forwarded-for")) ??
    firstValidIp(headers.get("x-real-ip")) ??
    "unknown"
  );
}
