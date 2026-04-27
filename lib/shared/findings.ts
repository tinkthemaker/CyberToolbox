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
