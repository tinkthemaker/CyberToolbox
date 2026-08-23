import { describe, expect, it } from "vitest";
import { analyzeJwt } from "@/lib/jwt/analyze";
import { parseJwt } from "@/lib/jwt/parse";

function encode(value: unknown): string {
  return Buffer.from(typeof value === "string" ? value : JSON.stringify(value)).toString("base64url");
}

function token(header: unknown, payload: unknown, signature = ""): string {
  return `${encode(header)}.${encode(payload)}.${signature}`;
}

describe("parseJwt", () => {
  it("strips Bearer and parses two- and three-segment tokens", () => {
    const two = parseJwt(`Bearer ${token({ alg: "none" }, { sub: "alice" })}`);
    expect(two.ok && two.jwt.hasSignature).toBe(false);

    const three = parseJwt(token({ alg: "HS256" }, { sub: "alice" }, "c2ln"));
    expect(three.ok && three.jwt.hasSignature).toBe(true);
  });

  it("rejects malformed input and non-JSON headers", () => {
    expect(parseJwt("not-a-jwt").ok).toBe(false);
    expect(parseJwt(`${encode("not-json")}.${encode({})}.`).ok).toBe(false);
  });

  it("preserves a valid non-JSON payload as text", () => {
    const result = parseJwt(`${encode({ alg: "none" })}.${encode("plain text")}.`);
    expect(result.ok && result.jwt.payload).toBe("plain text");
  });
});

describe("analyzeJwt", () => {
  it("reports algorithm, signature, expiry, lifetime, claim, header, and sensitive-data findings", () => {
    const now = Math.floor(Date.now() / 1000);
    const result = parseJwt(
      token(
        { alg: "none", jku: "https://keys.example", x5u: "https://certs.example", jwk: { kty: "RSA" } },
        {
          exp: now - 10,
          iat: now - 40 * 86400,
          nbf: now + 1000,
          password: "secret",
        },
      ),
    );
    if (!result.ok) throw new Error(result.reason);
    const findings = analyzeJwt(result.jwt);
    const byId = new Map(findings.map((finding) => [finding.id, finding]));
    expect(byId.get("alg-none")?.severity).toBe("fail");
    expect(byId.get("no-signature")?.severity).toBe("info");
    expect(byId.get("exp-past")?.severity).toBe("fail");
    expect(byId.get("nbf-future")?.severity).toBe("info");
    expect(byId.get("lifetime-long")?.severity).toBe("warn");
    expect(byId.get("claim-iss-missing")?.severity).toBe("info");
    expect(byId.get("claim-aud-missing")?.severity).toBe("info");
    expect(byId.get("claim-sub-missing")?.severity).toBe("info");
    expect(byId.get("jku")?.severity).toBe("warn");
    expect(byId.get("x5u")?.severity).toBe("warn");
    expect(byId.get("jwk-embedded")?.severity).toBe("fail");
    expect(byId.get("sensitive-claims")?.severity).toBe("fail");
  });
});
