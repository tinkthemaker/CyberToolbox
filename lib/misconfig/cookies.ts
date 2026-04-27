import type { Finding } from "./types";

function parseSetCookies(headers: Headers): string[] {
  const getSetCookie = (headers as Headers & { getSetCookie?: () => string[] }).getSetCookie;
  if (typeof getSetCookie === "function") return getSetCookie.call(headers);
  const raw = headers.get("set-cookie");
  return raw ? [raw] : [];
}

export function checkCookies(headers: Headers, isHttps: boolean): Finding[] {
  const cookies = parseSetCookies(headers);
  if (cookies.length === 0) {
    return [
      {
        id: "no-cookies",
        name: "Cookies",
        severity: "info",
        detail: "No Set-Cookie headers were returned on this response.",
      },
    ];
  }

  return cookies.map((raw, i) => {
    const name = raw.split("=")[0]?.trim() ?? `cookie-${i}`;
    const lower = raw.toLowerCase();
    const hasSecure = /;\s*secure(\b|;|$)/.test(lower);
    const hasHttpOnly = /;\s*httponly(\b|;|$)/.test(lower);
    const sameSiteMatch = /;\s*samesite=(strict|lax|none)/i.exec(raw);
    const sameSite = sameSiteMatch?.[1].toLowerCase();

    const issues: string[] = [];
    if (isHttps && !hasSecure) issues.push("missing Secure");
    if (!hasHttpOnly) issues.push("missing HttpOnly");
    if (!sameSite) issues.push("missing SameSite");
    if (sameSite === "none" && !hasSecure) issues.push("SameSite=None without Secure");

    const severity: Finding["severity"] = issues.length === 0 ? "pass" : issues.length >= 2 ? "fail" : "warn";

    return {
      id: `cookie-${name}`,
      name: `Cookie: ${name}`,
      severity,
      detail:
        issues.length === 0
          ? "Cookie has Secure, HttpOnly, and SameSite set appropriately."
          : `Issues: ${issues.join(", ")}.`,
      value: raw.length > 160 ? raw.slice(0, 160) + "…" : raw,
      recommendation:
        issues.length === 0
          ? undefined
          : "Set Secure (HTTPS only), HttpOnly (block JS access), and SameSite=Lax or Strict.",
    };
  });
}
