import { describe, expect, it } from "vitest";
import { checkCookies } from "@/lib/misconfig/cookies";
import { checkDisclosure } from "@/lib/misconfig/disclosure";
import { checkSecurityHeaders } from "@/lib/misconfig/headers";

describe("security header checks", () => {
  it("grades CSP and HTTPS headers", () => {
    const missing = checkSecurityHeaders(new Headers(), true);
    expect(missing.find((finding) => finding.id === "csp")?.severity).toBe("fail");
    expect(missing.find((finding) => finding.id === "hsts")?.severity).toBe("fail");

    const http = checkSecurityHeaders(new Headers(), false);
    expect(http.find((finding) => finding.id === "https")?.severity).toBe("fail");

    const weakHsts = checkSecurityHeaders(
      new Headers({ "strict-transport-security": "max-age=3600" }),
      true,
    );
    expect(weakHsts.find((finding) => finding.id === "hsts")?.severity).toBe("warn");

    const headers = new Headers({
      "content-security-policy": "default-src 'self'",
      "strict-transport-security": "max-age=31536000; includeSubDomains",
      "x-frame-options": "DENY",
      "x-content-type-options": "nosniff",
      "referrer-policy": "strict-origin",
      "permissions-policy": "camera=()",
    });
    expect(checkSecurityHeaders(headers, true).filter((finding) => finding.severity === "fail")).toHaveLength(0);
  });
});

describe("cookie checks", () => {
  it("grades missing attributes and hardened cookies", () => {
    const weak = checkCookies(new Headers({ "set-cookie": "session=value" }), true);
    expect(weak[0].severity).toBe("fail");

    const headers = new Headers();
    Object.defineProperty(headers, "getSetCookie", {
      value: () => [
        "session=value; Secure; HttpOnly; SameSite=Lax",
        "prefs=value; Secure; HttpOnly; SameSite=Strict",
      ],
    });
    expect(checkCookies(headers, true).map((finding) => finding.severity)).toEqual(["pass", "pass"]);
  });
});

describe("disclosure checks", () => {
  it("flags technology disclosure and returns a clean finding otherwise", () => {
    const findings = checkDisclosure(
      new Headers({ server: "nginx/1.24.0", "x-powered-by": "Express" }),
    );
    expect(findings.find((finding) => finding.id === "server-banner")?.severity).toBe("warn");
    expect(findings.find((finding) => finding.id === "x-powered-by")?.severity).toBe("warn");
    expect(checkDisclosure(new Headers())[0].id).toBe("no-disclosure");
  });
});
