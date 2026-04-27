export type { Severity, Finding, FindingGroup } from "@/lib/shared/findings";
import type { FindingGroup } from "@/lib/shared/findings";

export type ScanReport = {
  target: {
    input: string;
    finalUrl: string;
    status: number;
    redirects: string[];
    responseTimeMs: number;
  };
  groups: FindingGroup[];
  summary: {
    pass: number;
    warn: number;
    fail: number;
    info: number;
    score: number;
  };
};
