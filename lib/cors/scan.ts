import { safeFetch } from "@/lib/security/safe-fetch";
import type { Finding, FindingGroup } from "@/lib/shared/findings";
import type { CorsReport, ProbeMethod, ProbeResult } from "./types";

const ATTACKER_HOST = "evil-attacker.example";

type ProbeSpec = {
  id: string;
  label: string;
  origin: string | null;
  method: ProbeMethod;
};

function buildProbes(targetHost: string, isHttps: boolean): ProbeSpec[] {
  const scheme = isHttps ? "https" : "http";
  const probes: ProbeSpec[] = [
    { id: "baseline", label: "Baseline (no Origin)", origin: null, method: "GET" },
    {
      id: "arbitrary-origin",
      label: "Arbitrary cross-origin",
      origin: `https://${ATTACKER_HOST}`,
      method: "GET",
    },
    { id: "null-origin", label: "Origin: null", origin: "null", method: "GET" },
    {
      id: "suffix-bypass",
      label: "Suffix bypass — attacker domain ends in target",
      origin: `https://attacker${targetHost.replace(/\./g, "")}.example`,
      method: "GET",
    },
    {
      id: "prefix-bypass",
      label: "Prefix bypass — target as a subdomain of attacker",
      origin: `https://${targetHost}.${ATTACKER_HOST}`,
      method: "GET",
    },
    {
      id: "subdomain-trust",
      label: "Subdomain — attacker.<target>",
      origin: `${scheme}://attacker.${targetHost}`,
      method: "GET",
    },
    {
      id: "preflight",
      label: "Preflight (OPTIONS) for PUT + auth header",
      origin: `https://${ATTACKER_HOST}`,
      method: "OPTIONS",
    },
  ];
  if (isHttps) {
    probes.splice(2, 0, {
      id: "scheme-downgrade",
      label: "Scheme downgrade — http://target",
      origin: `http://${targetHost}`,
      method: "GET",
    });
  }
  return probes;
}

async function runProbe(url: string, spec: ProbeSpec): Promise<ProbeResult> {
  const headers: Record<string, string> = {};
  if (spec.origin !== null) headers["Origin"] = spec.origin;
  if (spec.method === "OPTIONS") {
    headers["Access-Control-Request-Method"] = "PUT";
    headers["Access-Control-Request-Headers"] = "authorization,content-type";
  }

  const res = await safeFetch(url, { method: spec.method, headers });
  if (!res.ok) {
    return {
      id: spec.id,
      label: spec.label,
      sentOrigin: spec.origin,
      method: spec.method,
      status: 0,
      reflectsOrigin: false,
      error: res.reason,
    };
  }
  const h = res.data.headers;
  const acao = h.get("access-control-allow-origin") ?? undefined;
  const reflects = !!(spec.origin && acao && acao.toLowerCase() === spec.origin.toLowerCase());
  return {
    id: spec.id,
    label: spec.label,
    sentOrigin: spec.origin,
    method: spec.method,
    status: res.data.status,
    acao,
    acac: h.get("access-control-allow-credentials") ?? undefined,
    acam: h.get("access-control-allow-methods") ?? undefined,
    acah: h.get("access-control-allow-headers") ?? undefined,
    acema: h.get("access-control-expose-headers") ?? undefined,
    vary: h.get("vary") ?? undefined,
    reflectsOrigin: reflects,
  };
}

function isCredentialed(p: ProbeResult): boolean {
  return p.acac?.toLowerCase() === "true";
}

function analyze(probes: ProbeResult[]): FindingGroup[] {
  const findings: Finding[] = [];
  const byId = new Map(probes.map((p) => [p.id, p]));

  const baseline = byId.get("baseline");
  const corsActive = probes.some((p) => p.acao !== undefined);
  if (!corsActive) {
    findings.push({
      id: "no-cors",
      name: "No CORS headers in any response",
      severity: "info",
      detail:
        "The endpoint never returns Access-Control-Allow-Origin under any tested Origin. Cross-origin browsers will refuse credentialed reads — usually fine.",
    });
  }

  const arb = byId.get("arbitrary-origin");
  if (arb && arb.acao === "*" && isCredentialed(arb)) {
    findings.push({
      id: "wildcard-with-credentials",
      name: "ACAO=* with credentials",
      severity: "fail",
      detail:
        "Server returns Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true. Browsers will block the response, but the server is misconfigured and likely also wrong elsewhere.",
      value: `ACAO=${arb.acao}; ACAC=${arb.acac}`,
      recommendation: "Echo a specific origin from an allow-list, never '*' when credentials are enabled.",
    });
  }

  if (arb && arb.reflectsOrigin && isCredentialed(arb)) {
    findings.push({
      id: "reflective-with-credentials",
      name: "Origin reflection + credentials (CRITICAL)",
      severity: "fail",
      detail:
        "Server reflects an arbitrary Origin into ACAO and sets ACAC=true. Any web page can read authenticated responses from this endpoint when a victim is logged in.",
      value: `Origin sent: ${arb.sentOrigin} → ACAO=${arb.acao}, ACAC=${arb.acac}`,
      recommendation: "Validate Origin against an explicit allow-list before echoing it.",
    });
  } else if (arb && arb.reflectsOrigin) {
    findings.push({
      id: "reflective-no-credentials",
      name: "Origin reflection without credentials",
      severity: "warn",
      detail:
        "Server reflects an arbitrary Origin but does not set ACAC=true. No credentialed read, but other endpoints under the same handler may differ.",
      value: `Origin sent: ${arb.sentOrigin} → ACAO=${arb.acao}`,
    });
  }

  const nullP = byId.get("null-origin");
  if (nullP && (nullP.acao === "null" || nullP.reflectsOrigin)) {
    findings.push({
      id: "null-origin-trusted",
      name: "Trusts Origin: null",
      severity: isCredentialed(nullP) ? "fail" : "warn",
      detail:
        "Server allows the literal 'null' origin. Sandboxed iframes, file:// pages, and data: URLs send Origin: null — an attacker can spawn one and bypass CORS.",
      value: `ACAO=${nullP.acao}; ACAC=${nullP.acac ?? "(none)"}`,
      recommendation: "Never include 'null' in your CORS allow-list.",
    });
  }

  for (const probeId of ["suffix-bypass", "prefix-bypass", "subdomain-trust"] as const) {
    const p = byId.get(probeId);
    if (!p) continue;
    if (p.reflectsOrigin) {
      findings.push({
        id: `${probeId}-trusted`,
        name: `${p.label} accepted`,
        severity: isCredentialed(p) ? "fail" : "warn",
        detail:
          probeId === "subdomain-trust"
            ? "An arbitrary subdomain of the target is trusted. If any subdomain hosts attacker-controlled content (uploads, customer-facing markdown, takeover-prone DNS), it can read this endpoint."
            : "Naive Origin matching: a domain similar to (but not actually) the target was accepted. Likely a regex or substring check rather than a strict allow-list.",
        value: `Origin sent: ${p.sentOrigin} → ACAO=${p.acao}`,
        recommendation: "Use exact-match comparison against an allow-list, not endsWith / startsWith / regex.",
      });
    }
  }

  const downgrade = byId.get("scheme-downgrade");
  if (downgrade && downgrade.reflectsOrigin) {
    findings.push({
      id: "scheme-downgrade-trusted",
      name: "Trusts http:// origin of HTTPS target",
      severity: isCredentialed(downgrade) ? "fail" : "warn",
      detail:
        "An http:// version of the target's hostname is trusted. Active network attackers can mount a man-in-the-middle on the http origin and read this endpoint.",
      value: `Origin sent: ${downgrade.sentOrigin} → ACAO=${downgrade.acao}`,
      recommendation: "Only allow https:// origins in your CORS list.",
    });
  }

  // Vary: Origin hygiene
  for (const p of probes) {
    if (p.acao && p.acao !== "*" && p.id === "arbitrary-origin") {
      const varyHasOrigin = !!p.vary?.split(",").some((v) => v.trim().toLowerCase() === "origin");
      if (!varyHasOrigin) {
        findings.push({
          id: "vary-missing",
          name: "Vary: Origin missing on dynamic ACAO",
          severity: "warn",
          detail:
            "ACAO varies by request Origin but the response doesn't include 'Vary: Origin'. CDNs and shared caches may serve one user's ACAO to another.",
          value: `Vary=${p.vary ?? "(none)"}`,
          recommendation: "Add 'Vary: Origin' whenever ACAO is computed from the request.",
        });
        break;
      }
    }
  }

  // Preflight summary
  const pre = byId.get("preflight");
  if (pre && pre.acam) {
    const methods = pre.acam.split(",").map((m) => m.trim().toUpperCase());
    if (methods.includes("*") || methods.length >= 6) {
      findings.push({
        id: "preflight-broad-methods",
        name: "Preflight allows broad methods",
        severity: "info",
        detail:
          "Preflight returns a wide method list. Not a vulnerability on its own; pair with the reflection findings to assess impact.",
        value: `Allow-Methods: ${pre.acam}`,
      });
    }
  }

  // If nothing fired, give a positive note.
  if (findings.length === 0 && corsActive) {
    findings.push({
      id: "cors-ok",
      name: "No obvious CORS bypasses",
      severity: "pass",
      detail: "Tested origins were not echoed and credentials were handled cautiously across probes.",
    });
  }

  // Always show baseline status as info if it's an unusual response.
  if (baseline && baseline.status >= 400) {
    findings.push({
      id: "baseline-non-2xx",
      name: `Baseline returned ${baseline.status}`,
      severity: "info",
      detail:
        "The endpoint did not return 2xx without an Origin. Probe responses may be coming from an error path with different CORS behaviour than the live API.",
    });
  }

  return [{ id: "cors", title: "CORS findings", findings }];
}

function summarise(groups: FindingGroup[]): CorsReport["summary"] {
  let pass = 0,
    warn = 0,
    fail = 0,
    info = 0;
  for (const g of groups) {
    for (const f of g.findings) {
      if (f.severity === "pass") pass++;
      else if (f.severity === "warn") warn++;
      else if (f.severity === "fail") fail++;
      else info++;
    }
  }
  return { pass, warn, fail, info };
}

export async function runCorsScan(
  input: string,
): Promise<{ ok: true; report: CorsReport } | { ok: false; reason: string }> {
  const initial = await safeFetch(input, { method: "GET" });
  if (!initial.ok) return { ok: false, reason: initial.reason };
  const finalUrl = initial.data.finalUrl;
  const targetUrl = new URL(finalUrl);
  const isHttps = targetUrl.protocol === "https:";

  const specs = buildProbes(targetUrl.hostname, isHttps);
  const probes = await Promise.all(specs.map((s) => runProbe(finalUrl, s)));
  const groups = analyze(probes);

  return {
    ok: true,
    report: {
      target: {
        input,
        finalUrl,
        status: initial.data.status,
        responseTimeMs: initial.data.responseTimeMs,
        redirects: initial.data.redirects,
      },
      probes,
      groups,
      summary: summarise(groups),
    },
  };
}
