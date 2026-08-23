import { describe, expect, it, vi } from "vitest";

describe("rate limiting", () => {
  it("uses hardened client-key precedence", async () => {
    vi.resetModules();
    const { clientKeyFromHeaders } = await import("@/lib/security/rate-limit");
    expect(clientKeyFromHeaders(new Headers({
      "x-vercel-forwarded-for": "203.0.113.10",
      "x-real-ip": "198.51.100.20",
      "x-forwarded-for": "192.0.2.30, 192.0.2.40",
    }))).toBe("203.0.113.10");
    expect(clientKeyFromHeaders(new Headers({
      "x-real-ip": "198.51.100.20",
      "x-forwarded-for": "192.0.2.30, 192.0.2.40",
    }))).toBe("198.51.100.20");
    expect(clientKeyFromHeaders(new Headers({
      "x-forwarded-for": "192.0.2.30, 192.0.2.40",
    }))).toBe("192.0.2.40");
    expect(clientKeyFromHeaders(new Headers({ "x-forwarded-for": "not-an-ip" }))).toBe("unknown");
    expect(clientKeyFromHeaders(new Headers())).toBe("unknown");
  });

  it("trips after twelve requests with a useful retry time", async () => {
    vi.resetModules();
    const { rateLimit } = await import("@/lib/security/rate-limit");
    for (let i = 0; i < 12; i++) expect(rateLimit("client")).toEqual({ ok: true });
    const blocked = rateLimit("client");
    expect(blocked.ok).toBe(false);
    if (!blocked.ok) expect(blocked.retryAfterSec).toBeGreaterThanOrEqual(1);
  });
});
