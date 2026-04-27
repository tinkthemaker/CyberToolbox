export type Severity = "pass" | "warn" | "fail" | "info";

export type Finding = {
  id: string;
  name: string;
  severity: Severity;
  detail: string;
  value?: string;
  recommendation?: string;
};

export type FindingGroup = {
  id: string;
  title: string;
  findings: Finding[];
};

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
