import type { Finding, FindingGroup } from "@/lib/shared/findings";

export type SecurityTxtAnalysisInput = {
  body: string;
  fetchedUrl: string;
  now?: Date;
};

export type SecurityTxtSummary = {
  score: number;
  pass: number;
  warn: number;
  fail: number;
  info: number;
};

export type SecurityTxtReport = {
  target: {
    finalUrl: string;
    responseTimeMs?: number;
    status?: number;
    redirects?: string[];
    location: "well-known" | "root" | "other";
  };
  summary: SecurityTxtSummary;
  fields: Record<string, string[]>;
  malformedLines: number[];
  groups: FindingGroup[];
};

type ParsedSecurityTxt = {
  fields: Record<string, string[]>;
  malformedLines: number[];
};

const FIELD_RE = /^([A-Za-z][A-Za-z0-9_-]*):\s*(.*)$/;
const WELL_KNOWN_PATH = "/.well-known/security.txt";
const RFC3339_DATE_TIME_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

function addField(fields: Record<string, string[]>, name: string, value: string) {
  const canonical = name
    .split("-")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
    .join("-");
  fields[canonical] = [...(fields[canonical] ?? []), value.trim()];
}

export function parseSecurityTxt(body: string): ParsedSecurityTxt {
  const fields: Record<string, string[]> = {};
  const malformedLines: number[] = [];

  const lines = clearSignedText(body);
  lines.forEach((rawLine, index) => {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) return;

    const match = FIELD_RE.exec(line);
    if (!match) {
      malformedLines.push(index + 1);
      return;
    }

    addField(fields, match[1], match[2]);
  });

  return { fields, malformedLines };
}

function clearSignedText(body: string): string[] {
  const lines = body.split(/\r?\n/);
  if (lines[0] !== "-----BEGIN PGP SIGNED MESSAGE-----") return lines;

  const cleartextStart = lines.findIndex((line, index) => index > 0 && line === "") + 1;
  const signatureStart = lines.findIndex(
    (line, index) => index >= cleartextStart && line === "-----BEGIN PGP SIGNATURE-----",
  );
  if (cleartextStart === 0 || signatureStart === -1) return lines;

  return lines.slice(cleartextStart, signatureStart).map((line) =>
    line.startsWith("- ") ? line.slice(2) : line,
  );
}

function finding(input: Finding): Finding {
  return input;
}

function countSummary(groups: FindingGroup[]): SecurityTxtSummary {
  const findings = groups.flatMap((group) => group.findings);
  const pass = findings.filter((item) => item.severity === "pass").length;
  const warn = findings.filter((item) => item.severity === "warn").length;
  const fail = findings.filter((item) => item.severity === "fail").length;
  const info = findings.filter((item) => item.severity === "info").length;
  const score = Math.max(0, Math.min(100, 100 - fail * 30 - warn * 10));
  return { score, pass, warn, fail, info };
}

function parseDate(value: string): Date | null {
  const match = RFC3339_DATE_TIME_RE.exec(value);
  if (!match) return null;
  const [, yearText, monthText, dayText, hourText, minuteText, secondText] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  if (
    month < 1 || month > 12 || day < 1 || day > new Date(Date.UTC(year, month, 0)).getUTCDate() ||
    hour > 23 || minute > 59 || second > 59
  ) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function isContactUri(value: string): boolean {
  try {
    const uri = new URL(value);
    if (!uri.protocol) return false;
    if (uri.protocol === "mailto:") return /^[^@\s]+@[^@\s]+$/.test(uri.pathname);
    return uri.href.length > uri.protocol.length;
  } catch {
    return false;
  }
}

function locationKind(fetchedUrl: string): SecurityTxtReport["target"]["location"] {
  try {
    const path = new URL(fetchedUrl).pathname;
    if (path === WELL_KNOWN_PATH) return "well-known";
    if (path === "/security.txt") return "root";
  } catch {
    // fall through
  }
  return "other";
}

function analyzeRequiredFields(fields: Record<string, string[]>, now: Date): FindingGroup {
  const findings: Finding[] = [];
  const contacts = fields.Contact ?? [];
  if (contacts.length === 0) {
    findings.push(
      finding({
        id: "contact-missing",
        name: "Missing Contact field",
        severity: "fail",
        detail: "security.txt requires at least one Contact field so researchers know where to send vulnerability reports.",
        recommendation: "Add a monitored mailto: address or HTTPS contact URL, for example: Contact: mailto:security@example.com.",
      }),
    );
  } else if (contacts.every(isContactUri)) {
    findings.push(
      finding({
        id: "contact-present",
        name: "Contact field present",
        severity: "pass",
        detail: `Found ${contacts.length} vulnerability disclosure contact value${contacts.length === 1 ? "" : "s"}.`,
        value: contacts.join("\n"),
        recommendation: "Keep this contact monitored and make sure reports receive a timely response.",
      }),
    );
  } else {
    findings.push(
      finding({
        id: "contact-invalid",
        name: "Contact field contains an invalid URI",
        severity: "fail",
        detail: "Every Contact value must be a URI. Email addresses require the mailto: scheme.",
        value: contacts.join("\n"),
        recommendation: "Use a URI such as mailto:security@example.com or https://example.com/security/contact.",
      }),
    );
  }

  const expiresValues = fields.Expires ?? [];
  if (expiresValues.length === 0) {
    findings.push(
      finding({
        id: "expires-missing",
        name: "Missing Expires field",
        severity: "fail",
        detail: "RFC 9116 requires an Expires field so researchers can tell whether the policy is current.",
        recommendation: "Add an ISO 8601 timestamp and refresh it before the date passes.",
      }),
    );
  } else if (expiresValues.length > 1) {
    findings.push(
      finding({
        id: "expires-duplicate",
        name: "Multiple Expires fields",
        severity: "fail",
        detail: "RFC 9116 requires exactly one Expires field.",
        value: expiresValues.join("\n"),
        recommendation: "Keep one RFC 3339 Expires timestamp and remove duplicate fields.",
      }),
    );
  } else {
    const expires = expiresValues[0];
    const expiryDate = parseDate(expires);
    if (!expiryDate) {
      findings.push(
        finding({
          id: "expires-invalid",
          name: "Invalid Expires value",
          severity: "fail",
          detail: "The Expires field is present but could not be parsed as a date.",
          value: expires,
          recommendation: "Use an ISO 8601 timestamp such as 2026-06-01T00:00:00Z.",
        }),
      );
    } else if (expiryDate <= now) {
      findings.push(
        finding({
          id: "expires-expired",
          name: "Expired security.txt",
          severity: "fail",
          detail: "The Expires field is in the past, so researchers cannot rely on the published disclosure instructions.",
          value: expires,
          recommendation: "Publish an updated security.txt file with a future Expires value.",
        }),
      );
    } else {
      findings.push(
        finding({
          id: "expires-valid",
          name: "Expires field is current",
          severity: "pass",
          detail: "The Expires field is present and points to a future date.",
          value: expires,
          recommendation: "Refresh this date as part of regular security program maintenance.",
        }),
      );
    }
  }

  return { id: "required", title: "Required fields", findings };
}

function analyzeLocation(fields: Record<string, string[]>, fetchedUrl: string): FindingGroup {
  const findings: Finding[] = [];
  const kind = locationKind(fetchedUrl);

  if (kind === "well-known") {
    findings.push(
      finding({
        id: "location-well-known",
        name: "Preferred location used",
        severity: "pass",
        detail: "The file was found at /.well-known/security.txt, the preferred RFC 9116 location.",
        value: fetchedUrl,
      }),
    );
  } else {
    findings.push(
      finding({
        id: "location-root",
        name: "Fallback root location used",
        severity: "warn",
        detail: "The file was found at /security.txt instead of the preferred /.well-known/security.txt path.",
        value: fetchedUrl,
        recommendation: "Serve the file from /.well-known/security.txt and optionally redirect /security.txt there.",
      }),
    );
  }

  const canonicals = fields.Canonical ?? [];
  if (canonicals.length === 0) {
    findings.push(
      finding({
        id: "canonical-missing",
        name: "Canonical field missing",
        severity: "info",
        detail: "Canonical is optional, but it helps researchers identify the authoritative URL for this policy.",
        recommendation: "Add Canonical: https://example.com/.well-known/security.txt if this file is served from multiple places.",
      }),
    );
  } else if (!canonicals.includes(fetchedUrl)) {
    findings.push(
      finding({
        id: "canonical-mismatch",
        name: "Canonical does not match fetched URL",
        severity: "warn",
        detail: "The Canonical field points somewhere other than the URL that was audited.",
        value: canonicals.join("\n"),
        recommendation: "Update Canonical to the authoritative /.well-known/security.txt URL, or redirect duplicate locations to it.",
      }),
    );
  } else {
    findings.push(
      finding({
        id: "canonical-match",
        name: "Canonical matches fetched URL",
        severity: "pass",
        detail: "The Canonical field matches the audited security.txt URL.",
        value: canonicals.join("\n"),
      }),
    );
  }

  return { id: "location", title: "Location and canonical URL", findings };
}

function analyzeOptionalProgramFields(fields: Record<string, string[]>): FindingGroup {
  const optionalFields = ["Policy", "Encryption", "Acknowledgments", "Hiring", "Preferred-Languages"];
  const findings: Finding[] = optionalFields.map((fieldName) => {
    const values = fields[fieldName] ?? [];
    if (values.length === 0) {
      return finding({
        id: `${fieldName.toLowerCase()}-missing`,
        name: `${fieldName} not published`,
        severity: "info",
        detail: `${fieldName} is optional, but publishing it can make the vulnerability disclosure process clearer.`,
        recommendation: `Add ${fieldName}: if your security program has a stable value for it.`,
      });
    }

    return finding({
      id: `${fieldName.toLowerCase()}-present`,
      name: `${fieldName} published`,
      severity: "pass",
      detail: `Found ${fieldName} value${values.length === 1 ? "" : "s"}.`,
      value: values.join("\n"),
    });
  });

  return { id: "program", title: "Disclosure program signals", findings };
}

function analyzeSyntax(malformedLines: number[]): FindingGroup {
  if (malformedLines.length === 0) {
    return {
      id: "syntax",
      title: "Syntax",
      findings: [
        finding({
          id: "syntax-valid",
          name: "No malformed lines found",
          severity: "pass",
          detail: "Every non-empty, non-comment line follows the Field: value format.",
        }),
      ],
    };
  }

  return {
    id: "syntax",
    title: "Syntax",
    findings: [
      finding({
        id: "malformed-lines",
        name: "Malformed lines found",
        severity: "warn",
        detail: `Found ${malformedLines.length} line${malformedLines.length === 1 ? "" : "s"} that do not follow the Field: value format.`,
        value: malformedLines.map((line) => `Line ${line}`).join("\n"),
        recommendation: "Remove free-form text or convert it to RFC 9116 fields with a colon separator.",
      }),
    ],
  };
}

export function analyzeSecurityTxt(input: SecurityTxtAnalysisInput): SecurityTxtReport {
  const now = input.now ?? new Date();
  const parsed = parseSecurityTxt(input.body);
  const groups = [
    analyzeRequiredFields(parsed.fields, now),
    analyzeLocation(parsed.fields, input.fetchedUrl),
    analyzeOptionalProgramFields(parsed.fields),
    analyzeSyntax(parsed.malformedLines),
  ];

  return {
    target: {
      finalUrl: input.fetchedUrl,
      location: locationKind(input.fetchedUrl),
    },
    summary: countSummary(groups),
    fields: parsed.fields,
    malformedLines: parsed.malformedLines,
    groups,
  };
}
