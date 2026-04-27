import type { FindingGroup } from "@/lib/shared/findings";

export type ProbeMethod = "GET" | "OPTIONS";

export type ProbeResult = {
  id: string;
  label: string;
  sentOrigin: string | null;
  method: ProbeMethod;
  status: number;
  acao?: string;
  acac?: string;
  acam?: string;
  acah?: string;
  acema?: string;
  vary?: string;
  reflectsOrigin: boolean;
  error?: string;
};

export type CorsReport = {
  target: {
    input: string;
    finalUrl: string;
    status: number;
    responseTimeMs: number;
    redirects: string[];
  };
  probes: ProbeResult[];
  groups: FindingGroup[];
  summary: {
    pass: number;
    warn: number;
    fail: number;
    info: number;
  };
};
