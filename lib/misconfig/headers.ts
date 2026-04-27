import type { Finding } from "./types";

export function checkSecurityHeaders(headers: Headers, isHttps: boolean): Finding[] {
  const out: Finding[] = [];
  const csp = headers.get("content-security-policy");
  out.push({
    id: "csp",
    name: "Content-Security-Policy",
    severity: csp ? "pass" : "fail",
    detail: csp
      ? "CSP is set. Review it for unsafe-inline / unsafe-eval / wildcard sources."
      : "No CSP header. CSP is the primary defence against XSS and data injection.",
    value: csp ?? undefined,
    recommendation: csp
      ? undefined
      : "Add a strict CSP, starting with default-src 'self' and tightening per-source.",
  });

  if (isHttps) {
    const hsts = headers.get("strict-transport-security");
    const maxAge = hsts ? /max-age=(\d+)/i.exec(hsts)?.[1] : undefined;
    const ageNum = maxAge ? Number(maxAge) : 0;
    out.push({
      id: "hsts",
      name: "Strict-Transport-Security",
      severity: !hsts ? "fail" : ageNum < 15552000 ? "warn" : "pass",
      detail: !hsts
        ? "HSTS missing on an HTTPS origin. Browsers can be downgraded over the network."
        : ageNum < 15552000
          ? "HSTS present but max-age is short (<6 months)."
          : "HSTS is set with a healthy max-age.",
      value: hsts ?? undefined,
      recommendation:
        !hsts || ageNum < 15552000
          ? "Set Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
          : undefined,
    });
  } else {
    out.push({
      id: "https",
      name: "HTTPS",
      severity: "fail",
      detail: "Origin is served over plaintext HTTP. HSTS cannot be evaluated.",
      recommendation: "Serve over HTTPS and redirect HTTP → HTTPS.",
    });
  }

  const xfo = headers.get("x-frame-options");
  const cspFrameAncestors = csp && /frame-ancestors\b/i.test(csp);
  out.push({
    id: "x-frame-options",
    name: "X-Frame-Options / frame-ancestors",
    severity: xfo || cspFrameAncestors ? "pass" : "fail",
    detail:
      xfo || cspFrameAncestors
        ? "Clickjacking protection is in place."
        : "No X-Frame-Options or CSP frame-ancestors directive. Page is framable.",
    value: xfo ?? (cspFrameAncestors ? "(via CSP frame-ancestors)" : undefined),
    recommendation:
      xfo || cspFrameAncestors ? undefined : "Set X-Frame-Options: DENY or CSP frame-ancestors 'none'.",
  });

  const xcto = headers.get("x-content-type-options");
  out.push({
    id: "x-content-type-options",
    name: "X-Content-Type-Options",
    severity: xcto?.toLowerCase().includes("nosniff") ? "pass" : "fail",
    detail: xcto?.toLowerCase().includes("nosniff")
      ? "MIME sniffing is disabled."
      : "Missing nosniff. Browsers may MIME-sniff responses.",
    value: xcto ?? undefined,
    recommendation: xcto?.toLowerCase().includes("nosniff")
      ? undefined
      : "Set X-Content-Type-Options: nosniff",
  });

  const referrer = headers.get("referrer-policy");
  out.push({
    id: "referrer-policy",
    name: "Referrer-Policy",
    severity: referrer ? "pass" : "warn",
    detail: referrer
      ? "Referrer policy is explicit."
      : "No Referrer-Policy. Default behaviour leaks full URLs cross-origin in some browsers.",
    value: referrer ?? undefined,
    recommendation: referrer ? undefined : "Set Referrer-Policy: strict-origin-when-cross-origin",
  });

  const permissions = headers.get("permissions-policy");
  out.push({
    id: "permissions-policy",
    name: "Permissions-Policy",
    severity: permissions ? "pass" : "warn",
    detail: permissions
      ? "Permissions-Policy is set."
      : "No Permissions-Policy. Powerful APIs (camera, geolocation, etc.) are not restricted.",
    value: permissions ?? undefined,
    recommendation: permissions
      ? undefined
      : "Set Permissions-Policy to opt out of features you don't use.",
  });

  return out;
}
