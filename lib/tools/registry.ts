export type ToolStatus = "live" | "soon";

export type Tool = {
  id: string;
  name: string;
  tagline: string;
  description: string;
  href: string;
  apiPath?: string;
  status: ToolStatus;
  owaspRefs?: string[];
  tags?: string[];
};

export const TOOLS: Tool[] = [
  {
    id: "misconfig-mapper",
    name: "Misconfig Mapper",
    tagline: "OWASP A05 in one click.",
    description:
      "Enter a URL and get a report card: missing security headers, exposed .git/.env, information disclosure, and cookie hygiene.",
    href: "/tools/misconfig-mapper",
    apiPath: "/api/tools/misconfig-mapper",
    status: "live",
    owaspRefs: ["A05:2021 - Security Misconfiguration"],
    tags: ["headers", "exposure", "cookies"],
  },
];

export function getTool(id: string): Tool | undefined {
  return TOOLS.find((t) => t.id === id);
}
