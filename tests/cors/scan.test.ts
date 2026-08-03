import { describe, expect, it } from "vitest";
import { analyze, buildProbes } from "@/lib/cors/scan";
import type { ProbeResult } from "@/lib/cors/types";

describe("CORS probe analysis", () => {
  it("builds honest suffix and prefix bypass origins", () => {
    const probes = buildProbes("example.com", false);
    const suffix = probes.find((probe) => probe.id === "suffix-bypass");
    const prefix = probes.find((probe) => probe.id === "prefix-bypass");
    expect(suffix?.origin?.endsWith("example.com")).toBe(true);
    expect(prefix?.origin?.startsWith("https://example.com")).toBe(true);
  });

  it("flags reflected credentials and missing Vary on any reflected origin", () => {
    const probes: ProbeResult[] = [
      {
        id: "baseline",
        label: "Baseline",
        sentOrigin: null,
        method: "GET",
        status: 200,
        reflectsOrigin: false,
      },
      {
        id: "arbitrary-origin",
        label: "Arbitrary",
        sentOrigin: "https://evil.example",
        method: "GET",
        status: 200,
        acao: "https://evil.example",
        acac: "true",
        reflectsOrigin: true,
      },
      {
        id: "suffix-bypass",
        label: "Suffix",
        sentOrigin: "https://notexample.com",
        method: "GET",
        status: 200,
        acao: "https://notexample.com",
        reflectsOrigin: true,
      },
    ];
    const findings = analyze(probes)[0].findings;
    expect(findings.find((finding) => finding.id === "reflective-with-credentials")?.severity).toBe("fail");
    expect(findings.filter((finding) => finding.id === "vary-missing")).toHaveLength(2);
  });
});
