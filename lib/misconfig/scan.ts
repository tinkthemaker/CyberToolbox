import { safeFetch } from "@/lib/security/safe-fetch";
import { checkSecurityHeaders } from "./headers";
import { checkDisclosure } from "./disclosure";
import { checkCookies } from "./cookies";
import { runProbes } from "./probes";
import type { FindingGroup, ScanReport, Finding } from "./types";

const SEVERITY_WEIGHT: Record<Finding["severity"], number> = {
  pass: 1,
  warn: 0.5,
  fail: 0,
  info: -1,
};

function computeSummary(groups: FindingGroup[]): ScanReport["summary"] {
  let pass = 0,
    warn = 0,
    fail = 0,
    info = 0,
    weighted = 0,
    total = 0;
  for (const group of groups) {
    for (const f of group.findings) {
      if (f.severity === "pass") pass++;
      else if (f.severity === "warn") warn++;
      else if (f.severity === "fail") fail++;
      else info++;
      const w = SEVERITY_WEIGHT[f.severity];
      if (w >= 0) {
        weighted += w;
        total += 1;
      }
    }
  }
  const score = total === 0 ? 0 : Math.round((weighted / total) * 100);
  return { pass, warn, fail, info, score };
}

export async function runScan(input: string): Promise<
  | { ok: true; report: ScanReport }
  | { ok: false; reason: string }
> {
  const initial = await safeFetch(input, { method: "GET" });
  if (!initial.ok) return { ok: false, reason: initial.reason };

  const { finalUrl, status, headers, redirects, responseTimeMs } = initial.data;
  const isHttps = new URL(finalUrl).protocol === "https:";

  const groups: FindingGroup[] = [
    {
      id: "headers",
      title: "Security Headers",
      findings: checkSecurityHeaders(headers, isHttps),
    },
    {
      id: "disclosure",
      title: "Information Disclosure",
      findings: checkDisclosure(headers),
    },
    {
      id: "cookies",
      title: "Cookies",
      findings: checkCookies(headers, isHttps),
    },
    {
      id: "exposures",
      title: "File Exposure Probes",
      findings: await runProbes(finalUrl),
    },
  ];

  return {
    ok: true,
    report: {
      target: { input, finalUrl, status, redirects, responseTimeMs },
      groups,
      summary: computeSummary(groups),
    },
  };
}
