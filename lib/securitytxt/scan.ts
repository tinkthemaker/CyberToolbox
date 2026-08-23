import type { FindingGroup } from "@/lib/shared/findings";
import { safeFetch } from "@/lib/security/safe-fetch";
import { analyzeSecurityTxt, type SecurityTxtReport } from "./analyze";

function normalizeOrigin(input: string): string {
  const withScheme = /^https?:\/\//i.test(input) ? input : `https://${input}`;
  const url = new URL(withScheme);
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("unsupported protocol");
  }
  return url.origin;
}

function missingReport(origin: string, checkedUrls: string[]): SecurityTxtReport {
  const groups: FindingGroup[] = [
    {
      id: "availability",
      title: "Availability",
      findings: [
        {
          id: "securitytxt-missing",
          name: "security.txt not found",
          severity: "fail",
          detail: "Neither /.well-known/security.txt nor /security.txt returned a usable policy file.",
          value: checkedUrls.join("\n"),
          recommendation: "Publish a security.txt file at /.well-known/security.txt with at least Contact and Expires fields.",
        },
      ],
    },
  ];

  return {
    target: {
      finalUrl: origin,
      location: "other",
      status: 404,
      redirects: [],
    },
    summary: { score: 0, pass: 0, warn: 0, fail: 1, info: 0 },
    fields: {},
    malformedLines: [],
    groups,
  };
}

export async function runSecurityTxtAudit(
  inputUrl: string,
): Promise<{ ok: true; report: SecurityTxtReport } | { ok: false; reason: string }> {
  let origin: string;
  try {
    origin = normalizeOrigin(inputUrl);
  } catch {
    return { ok: false, reason: "Provide a valid http(s) URL or domain." };
  }

  const candidates = [`${origin}/.well-known/security.txt`, `${origin}/security.txt`];
  const checked: string[] = [];
  let lastNetworkError: string | null = null;
  let receivedHttpResponse = false;

  for (const candidate of candidates) {
    checked.push(candidate);
    const result = await safeFetch(candidate, {
      headers: { Accept: "text/plain,*/*;q=0.8" },
    });

    if (!result.ok) {
      lastNetworkError = result.reason;
      continue;
    }

    const { data } = result;
    receivedHttpResponse = true;
    if (data.status >= 200 && data.status < 300 && data.body.trim().length > 0) {
      const report = analyzeSecurityTxt({ body: data.body, fetchedUrl: data.finalUrl });
      report.target.status = data.status;
      report.target.responseTimeMs = data.responseTimeMs;
      report.target.redirects = data.redirects;
      return { ok: true, report };
    }
  }

  if (!receivedHttpResponse && lastNetworkError) {
    return { ok: false, reason: lastNetworkError };
  }

  return { ok: true, report: missingReport(origin, checked) };
}
