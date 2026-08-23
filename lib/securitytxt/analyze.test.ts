import { describe, expect, it } from "vitest";
import { analyzeSecurityTxt } from "./analyze";

const NOW = new Date("2026-01-15T00:00:00Z");
const LOCATION = "https://example.com/.well-known/security.txt";

function severities(report: ReturnType<typeof analyzeSecurityTxt>) {
  return report.groups.flatMap((group) => group.findings.map((finding) => [finding.id, finding.severity]));
}

describe("analyzeSecurityTxt", () => {
  it("passes a well-formed security.txt with required contact and future expiry", () => {
    const report = analyzeSecurityTxt({
      body: [
        "Contact: mailto:security@example.com",
        "Expires: 2026-06-01T00:00:00Z",
        "Canonical: https://example.com/.well-known/security.txt",
        "Policy: https://example.com/security-policy",
        "Encryption: https://example.com/pgp-key.txt",
        "Preferred-Languages: en, es",
      ].join("\n"),
      fetchedUrl: LOCATION,
      now: NOW,
    });

    expect(report.summary.fail).toBe(0);
    expect(report.summary.score).toBeGreaterThanOrEqual(85);
    expect(severities(report)).toContainEqual(["contact-present", "pass"]);
    expect(severities(report)).toContainEqual(["expires-valid", "pass"]);
    expect(report.fields.Contact).toEqual(["mailto:security@example.com"]);
  });

  it("fails when Contact is missing", () => {
    const report = analyzeSecurityTxt({
      body: "Expires: 2026-06-01T00:00:00Z\nPolicy: https://example.com/security-policy",
      fetchedUrl: LOCATION,
      now: NOW,
    });

    expect(severities(report)).toContainEqual(["contact-missing", "fail"]);
    expect(report.summary.fail).toBe(1);
    expect(report.summary.score).toBeLessThan(80);
  });

  it("fails expired Expires fields", () => {
    const report = analyzeSecurityTxt({
      body: "Contact: mailto:security@example.com\nExpires: 2025-01-01T00:00:00Z",
      fetchedUrl: LOCATION,
      now: NOW,
    });

    expect(severities(report)).toContainEqual(["expires-expired", "fail"]);
  });

  it("rejects non-URI contacts and invalid, missing, or duplicate Expires values", () => {
    const invalidContact = analyzeSecurityTxt({
      body: "Contact: security@example.com\nExpires: 2026-06-01T00:00:00Z",
      fetchedUrl: LOCATION,
      now: NOW,
    });
    expect(severities(invalidContact)).toContainEqual(["contact-invalid", "fail"]);

    const missingExpiry = analyzeSecurityTxt({
      body: "Contact: mailto:security@example.com",
      fetchedUrl: LOCATION,
      now: NOW,
    });
    expect(severities(missingExpiry)).toContainEqual(["expires-missing", "fail"]);

    const duplicateExpiry = analyzeSecurityTxt({
      body: "Contact: mailto:security@example.com\nExpires: 2026-06-01T00:00:00Z\nExpires: 2027-06-01T00:00:00Z",
      fetchedUrl: LOCATION,
      now: NOW,
    });
    expect(severities(duplicateExpiry)).toContainEqual(["expires-duplicate", "fail"]);

    const malformedExpiry = analyzeSecurityTxt({
      body: "Contact: mailto:security@example.com\nExpires: June 1, 2026",
      fetchedUrl: LOCATION,
      now: NOW,
    });
    expect(severities(malformedExpiry)).toContainEqual(["expires-invalid", "fail"]);
  });

  it("parses clear-signed policies without treating the PGP envelope as fields", () => {
    const report = analyzeSecurityTxt({
      body: [
        "-----BEGIN PGP SIGNED MESSAGE-----",
        "Hash: SHA256",
        "",
        "Contact: mailto:security@example.com",
        "Expires: 2026-06-01T00:00:00Z",
        "- Canonical: https://example.com/.well-known/security.txt",
        "-----BEGIN PGP SIGNATURE-----",
        "version: test",
        "-----END PGP SIGNATURE-----",
      ].join("\n"),
      fetchedUrl: LOCATION,
      now: NOW,
    });

    expect(report.fields).toMatchObject({
      Contact: ["mailto:security@example.com"],
      Expires: ["2026-06-01T00:00:00Z"],
      Canonical: [LOCATION],
    });
    expect(report.fields.Hash).toBeUndefined();
    expect(report.malformedLines).toEqual([]);
  });

  it("warns on malformed lines and canonical mismatch", () => {
    const report = analyzeSecurityTxt({
      body: [
        "Contact: mailto:security@example.com",
        "Expires: 2026-06-01T00:00:00Z",
        "Canonical: https://www.example.com/security.txt",
        "This is not a field",
      ].join("\n"),
      fetchedUrl: LOCATION,
      now: NOW,
    });

    expect(severities(report)).toContainEqual(["canonical-mismatch", "warn"]);
    expect(severities(report)).toContainEqual(["malformed-lines", "warn"]);
    expect(report.malformedLines).toEqual([4]);
  });
});
