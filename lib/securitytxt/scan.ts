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

function unavailableReport(origin: string, checkedUrls: string[], status: number): SecurityTxtReport {
  const missing = status === 404;
  const groups: FindingGroup[] = [
    {
      id: "availability",
      title: "Availability",
      findings: [
        {
          id: missing ? "securitytxt-missing" : "securitytxt-unavailable",
          name: missing ? "security.txt not found" : "security.txt could not be retrieved",
          severity: "fail",
          detail: missing
            ? "Neither /.well-known/security.txt nor /security.txt returned a usable policy file."
            : `The server responded with HTTP ${status} while the auditor looked for security.txt.`,
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
      status,
      redirects: [],
    },
    summary: { score: 0, pass: 0, warn: 0, fail: 1, info: 0 },
    fields: {},
    malformedLines: [],
    groups,
  };
}

function addRetrievalFindings(report: SecurityTxtReport, finalUrl: string, contentType: string | null): void {
  const findings: FindingGroup["findings"] = [];
  if (new URL(finalUrl).protocol !== "https:") {
    findings.push({
      id: "retrieval-http",
      name: "security.txt was retrieved over HTTP",
      severity: "fail",
      detail: "RFC 9116 requires security.txt to be retrieved over HTTPS.",
      value: finalUrl,
      recommendation: "Serve and redirect the policy to an HTTPS URL.",
    });
  }
  const mediaType = contentType?.split(";", 1)[0].trim().toLowerCase();
  if (mediaType !== "text/plain") {
    findings.push({
      id: "retrieval-content-type",
      name: "security.txt is not served as text/plain",
      severity: "fail",
      detail: "RFC 9116 requires the response media type to be text/plain.",
      value: contentType ?? "(missing Content-Type)",
      recommendation: "Return Content-Type: text/plain; charset=utf-8 for the policy.",
    });
  }
  if (findings.length === 0) return;
  report.groups.unshift({ id: "retrieval", title: "Retrieval requirements", findings });
  report.summary.fail += findings.length;
  report.summary.score = Math.max(0, report.summary.score - findings.length * 30);
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
  let lastStatus = 404;
  const deadlineMs = Date.now() + 14_000;

  for (const candidate of candidates) {
    checked.push(candidate);
    const result = await safeFetch(candidate, {
      headers: { Accept: "text/plain,*/*;q=0.8" },
      deadlineMs,
    });

    if (!result.ok) {
      lastNetworkError = result.reason;
      continue;
    }

    const { data } = result;
    receivedHttpResponse = true;
    lastStatus = data.status;
    if (data.status >= 200 && data.status < 300 && data.body.trim().length > 0) {
      const report = analyzeSecurityTxt({ body: data.body, fetchedUrl: data.finalUrl });
      report.target.status = data.status;
      report.target.responseTimeMs = data.responseTimeMs;
      report.target.redirects = data.redirects;
      addRetrievalFindings(report, data.finalUrl, data.headers.get("content-type"));
      return { ok: true, report };
    }
  }

  if (!receivedHttpResponse && lastNetworkError) {
    return { ok: false, reason: lastNetworkError };
  }

  return { ok: true, report: unavailableReport(origin, checked, lastStatus) };
}
