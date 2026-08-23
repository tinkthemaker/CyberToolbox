import { afterEach, describe, expect, it, vi } from "vitest";
import { clientKeyFromHeaders } from "./rate-limit";

describe("clientKeyFromHeaders", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("prefers Vercel's preserved client address", () => {
    vi.stubEnv("VERCEL", "1");
    const headers = new Headers({
      "x-vercel-forwarded-for": "203.0.113.10",
      "x-forwarded-for": "198.51.100.20",
    });

    expect(clientKeyFromHeaders(headers)).toBe("203.0.113.10");
  });

  it("does not allow arbitrary strings to become rate-limit keys", () => {
    vi.stubEnv("TRUST_PROXY_HEADERS", "1");
    const headers = new Headers({ "x-forwarded-for": "attacker-controlled-value" });

    expect(clientKeyFromHeaders(headers)).toBe("direct");
  });
});
