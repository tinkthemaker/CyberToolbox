import { describe, expect, it, vi } from "vitest";

describe("rate limiting", () => {
  it("uses hardened client-key precedence", async () => {
    vi.resetModules();
    const { clientKeyFromHeaders } = await import("@/lib/security/rate-limit");
    expect(clientKeyFromHeaders(new Headers({
      "x-vercel-forwarded-for": "vercel-client",
      "x-real-ip": "real-client",
      "x-forwarded-for": "left, right",
    }))).toBe("vercel-client");
    expect(clientKeyFromHeaders(new Headers({
      "x-real-ip": "real-client",
      "x-forwarded-for": "left, right",
    }))).toBe("real-client");
    expect(clientKeyFromHeaders(new Headers({ "x-forwarded-for": "left, right" }))).toBe("right");
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
