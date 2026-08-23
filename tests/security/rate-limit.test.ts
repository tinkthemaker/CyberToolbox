import { afterEach, describe, expect, it, vi } from "vitest";

describe("rate limiting", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("ignores forwarding headers when no trusted proxy is declared", async () => {
    vi.resetModules();
    vi.stubEnv("VERCEL", "");
    vi.stubEnv("TRUST_PROXY_HEADERS", "");
    const { clientKeyFromHeaders } = await import("@/lib/security/rate-limit");
    expect(clientKeyFromHeaders(new Headers({
      "x-vercel-forwarded-for": "1.2.3.4",
      "x-real-ip": "5.6.7.8",
      "x-forwarded-for": "9.9.9.9, 10.10.10.10",
    }))).toBe("direct");
    expect(clientKeyFromHeaders(new Headers())).toBe("direct");
  });

  it("uses hardened client-key precedence behind a trusted proxy", async () => {
    vi.resetModules();
    vi.stubEnv("TRUST_PROXY_HEADERS", "1");
    const { clientKeyFromHeaders } = await import("@/lib/security/rate-limit");
    expect(clientKeyFromHeaders(new Headers({
      "x-vercel-forwarded-for": "1.2.3.4",
      "x-real-ip": "5.6.7.8",
      "x-forwarded-for": "9.9.9.9, 10.10.10.10",
    }))).toBe("1.2.3.4");
    expect(clientKeyFromHeaders(new Headers({
      "x-real-ip": "5.6.7.8",
      "x-forwarded-for": "9.9.9.9, 10.10.10.10",
    }))).toBe("5.6.7.8");
    expect(clientKeyFromHeaders(new Headers({ "x-forwarded-for": "9.9.9.9, 10.10.10.10" }))).toBe("10.10.10.10");
    expect(clientKeyFromHeaders(new Headers())).toBe("direct");
  });

  it("rejects header values that are not IP addresses", async () => {
    vi.resetModules();
    vi.stubEnv("TRUST_PROXY_HEADERS", "1");
    const { clientKeyFromHeaders } = await import("@/lib/security/rate-limit");
    expect(clientKeyFromHeaders(new Headers({ "x-vercel-forwarded-for": "spoofed-token" }))).toBe("direct");
    expect(clientKeyFromHeaders(new Headers({ "x-real-ip": "not.an.ip" }))).toBe("direct");
    expect(clientKeyFromHeaders(new Headers({ "x-forwarded-for": "abc, def" }))).toBe("direct");
  });

  it("trips after twelve requests with a useful retry time", async () => {
    vi.resetModules();
    const { rateLimit } = await import("@/lib/security/rate-limit");
    for (let i = 0; i < 12; i++) expect(rateLimit("client")).toEqual({ ok: true });
    const blocked = rateLimit("client");
    expect(blocked.ok).toBe(false);
    if (!blocked.ok) expect(blocked.retryAfterSec).toBeGreaterThanOrEqual(1);
  });

  it("enforces a global cap independent of the per-client key", async () => {
    vi.resetModules();
    const { rateLimit } = await import("@/lib/security/rate-limit");
    let blockedAt = -1;
    for (let i = 0; i < 200; i++) {
      const result = rateLimit(`rotating-${i}`);
      if (!result.ok) {
        blockedAt = i;
        expect(result.retryAfterSec).toBeGreaterThanOrEqual(1);
        break;
      }
    }
    expect(blockedAt).toBe(120);
  });
});
