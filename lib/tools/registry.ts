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

export const SITE = {
  name: "Cyber Toolbox",
  description: "A growing collection of small, focused web-security tools.",
};

export function baseUrl(): string {
  if (process.env.SITE_URL) return process.env.SITE_URL.replace(/\/$/, "");
  if (process.env.VERCEL_URL) return `https://${process.env.VERCEL_URL}`;
  return "http://localhost:3000";
}

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
  {
    id: "jwt-inspector",
    name: "JWT Inspector",
    tagline: "Decode, audit, and crack weak HS256 secrets.",
    description:
      "Paste a JWT and see decoded header/payload, security findings (alg:none, kid injection, expired tokens, sensitive claims), and a built-in HS256 wordlist crack — all in your browser.",
    href: "/tools/jwt-inspector",
    status: "live",
    owaspRefs: ["A02:2021 - Cryptographic Failures"],
    tags: ["jwt", "crypto", "client-only"],
  },
  {
    id: "cors-tester",
    name: "CORS Tester",
    tagline: "Probe an endpoint's Origin policy.",
    description:
      "Sends a battery of Origin probes — reflection, null, suffix/prefix bypass, subdomain, scheme downgrade, and a preflight — and classifies the response. Flags the dangerous reflection-with-credentials pattern.",
    href: "/tools/cors-tester",
    apiPath: "/api/tools/cors-tester",
    status: "live",
    owaspRefs: ["A05:2021 - Security Misconfiguration"],
    tags: ["cors", "headers"],
  },
  {
    id: "cert-viewer",
    name: "TLS / Cert Viewer",
    tagline: "Inspect the live certificate chain.",
    description:
      "Opens a TLS handshake to a host, walks the certificate chain, and grades expiry, hostname match, signature algorithm, key strength, protocol version, and cipher.",
    href: "/tools/cert-viewer",
    apiPath: "/api/tools/cert-viewer",
    status: "live",
    owaspRefs: ["A02:2021 - Cryptographic Failures"],
    tags: ["tls", "certificates", "crypto"],
  },
];

export function getTool(id: string): Tool | undefined {
  return TOOLS.find((t) => t.id === id);
}

export function toolMetadata(id: string): { title: string; description: string } {
  const tool = getTool(id);
  if (!tool) return { title: "Not found", description: SITE.description };
  return { title: tool.name, description: tool.description };
}
