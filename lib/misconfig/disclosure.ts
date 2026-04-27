import type { Finding } from "./types";

const VERSION_RE = /[\/\s]\d+(\.\d+){1,3}\b/;

export function checkDisclosure(headers: Headers): Finding[] {
  const out: Finding[] = [];

  const server = headers.get("server");
  if (server) {
    const leaks = VERSION_RE.test(server);
    out.push({
      id: "server-banner",
      name: "Server header",
      severity: leaks ? "warn" : "info",
      detail: leaks
        ? "Server header reveals software and version. Helpful to attackers fingerprinting CVEs."
        : "Server header present without obvious version detail.",
      value: server,
      recommendation: leaks ? "Strip or generalise the Server header at the proxy layer." : undefined,
    });
  }

  const poweredBy = headers.get("x-powered-by");
  if (poweredBy) {
    out.push({
      id: "x-powered-by",
      name: "X-Powered-By",
      severity: "warn",
      detail: "Reveals server technology. Disable in framework config.",
      value: poweredBy,
      recommendation: "Remove this header (e.g. expressApp.disable('x-powered-by') or equivalent).",
    });
  }

  const aspNet = headers.get("x-aspnet-version") ?? headers.get("x-aspnetmvc-version");
  if (aspNet) {
    out.push({
      id: "aspnet-version",
      name: "ASP.NET version header",
      severity: "warn",
      detail: "Discloses ASP.NET / MVC version.",
      value: aspNet,
      recommendation: "Disable httpRuntime enableVersionHeader in web.config.",
    });
  }

  if (out.length === 0) {
    out.push({
      id: "no-disclosure",
      name: "Information disclosure",
      severity: "pass",
      detail: "No common technology-disclosure headers found.",
    });
  }

  return out;
}
