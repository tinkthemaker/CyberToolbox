import { isIP } from "node:net";

type Bucket = { count: number; resetAt: number };

const WINDOW_MS = 60_000;
const MAX_PER_WINDOW = 12;
const GLOBAL_MAX_PER_WINDOW = 120;
const MAX_BUCKETS = 1_000;

const GLOBAL_KEY = "\u0000global";

const buckets = new Map<string, Bucket>();
let lastSweepAt = 0;

function takeToken(
  key: string,
  max: number,
  now: number,
): { ok: true } | { ok: false; retryAfterSec: number } {
  const bucket = buckets.get(key);
  if (!bucket || bucket.resetAt <= now) {
    if (!bucket && buckets.size >= MAX_BUCKETS) evictSoonestExpiring();
    buckets.set(key, { count: 1, resetAt: now + WINDOW_MS });
    return { ok: true };
  }
  if (bucket.count >= max) {
    return { ok: false, retryAfterSec: Math.ceil((bucket.resetAt - now) / 1000) };
  }
  bucket.count += 1;
  return { ok: true };
}

function evictSoonestExpiring(): void {
  let victim: string | undefined;
  let earliest = Infinity;
  for (const [bucketKey, value] of buckets) {
    if (bucketKey === GLOBAL_KEY) continue;
    if (value.resetAt < earliest) {
      earliest = value.resetAt;
      victim = bucketKey;
    }
  }
  if (victim !== undefined) buckets.delete(victim);
}

export function rateLimit(key: string): { ok: true } | { ok: false; retryAfterSec: number } {
  const now = Date.now();
  if (now - lastSweepAt >= WINDOW_MS || buckets.size > MAX_BUCKETS) {
    for (const [bucketKey, value] of buckets) {
      if (value.resetAt <= now) buckets.delete(bucketKey);
    }
    lastSweepAt = now;
  }
  const global = takeToken(GLOBAL_KEY, GLOBAL_MAX_PER_WINDOW, now);
  if (!global.ok) return global;
  return takeToken(key, MAX_PER_WINDOW, now);
}

function trustsProxyHeaders(): boolean {
  return process.env.VERCEL === "1" || process.env.TRUST_PROXY_HEADERS === "1";
}

function firstValidIp(value: string | null): string | null {
  if (!value) return null;
  const first = value.split(",")[0]?.trim();
  return first && isIP(first) ? first : null;
}

// Forwarding headers are attacker-controlled unless a trusted proxy overwrites
// them before the request reaches the handler. They are only honored when the
// deployment declares such a proxy (Vercel edge, or TRUST_PROXY_HEADERS=1),
// and only when the value parses as an IP address. Otherwise every request
// shares a single bucket, and the global limiter bounds total throughput.
export function clientKeyFromHeaders(headers: Headers): string {
  if (!trustsProxyHeaders()) return "direct";
  const vercel = firstValidIp(headers.get("x-vercel-forwarded-for"));
  if (vercel) return vercel;
  const realIp = firstValidIp(headers.get("x-real-ip"));
  if (realIp) return realIp;
  const xff = headers.get("x-forwarded-for");
  if (xff) {
    const entries = xff.split(",").map((value) => value.trim()).filter(Boolean);
    const last = entries[entries.length - 1];
    if (last && isIP(last)) return last;
  }
  return "direct";
}
