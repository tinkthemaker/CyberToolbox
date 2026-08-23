import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Methodology",
  description: "How Cyber Toolbox scopes checks, assigns severity, and limits abuse risk.",
};

const sections = [
  {
    title: "Defensive scope",
    body:
      "Cyber Toolbox is designed for public, authorized checks that help owners understand basic web security posture. It does not crawl sites, brute force services, exploit findings, or attempt authentication bypass.",
  },
  {
    title: "Network safety",
    body:
      "Every server-side URL check is routed through an SSRF guard. The guard resolves hostnames before fetches, blocks private and reserved address space, rejects localhost-style names, and re-applies the same checks after redirects.",
  },
  {
    title: "Rate limiting",
    body:
      "API routes use a small in-memory per-IP limiter. It is intentionally simple for a portfolio deployment and can be swapped for Vercel KV or Upstash Redis if the project needs durable shared limits.",
  },
  {
    title: "Severity model",
    body:
      "Findings are graded as pass, info, warn, or fail. Fail means a missing or dangerous control. Warn means a weakness, ambiguity, stale value, or risky configuration. Info points out useful optional improvements without penalizing the target heavily.",
  },
  {
    title: "Evidence-first reports",
    body:
      "Reports favor concrete evidence: the exact header, policy field, certificate detail, response behavior, or parsed token claim that led to the finding. Recommendations are written as remediation guidance instead of generic warnings.",
  },
  {
    title: "Known limitations",
    body:
      "These tools provide focused checks, not a full security assessment. A clean report does not prove an application is secure. Network errors, CDN behavior, redirects, and intentionally unusual policies can also affect results.",
  },
];

const references = [
  ["OWASP Top 10", "https://owasp.org/www-project-top-ten/"],
  ["RFC 9116: security.txt", "https://www.rfc-editor.org/rfc/rfc9116"],
  ["MDN: Content Security Policy", "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
  ["CISA Known Exploited Vulnerabilities", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"],
  ["NIST SP 800-53", "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"],
];

export default function MethodologyPage() {
  return (
    <div className="space-y-10">
      <header className="max-w-3xl">
        <p className="text-xs uppercase tracking-widest text-accent-400/80">Project methodology</p>
        <h1 className="text-3xl md:text-4xl font-bold tracking-tight mt-1">How the toolbox thinks</h1>
        <p className="mt-4 text-slate-400 leading-relaxed">
          Cyber Toolbox is intentionally narrow: small tools, bounded checks, clear evidence, and
          defensive guardrails. The goal is to make security posture easier to discuss without
          pretending that automated checks replace a real assessment.
        </p>
      </header>

      <div className="grid md:grid-cols-2 gap-4">
        {sections.map((section) => (
          <section key={section.title} className="rounded-2xl border border-ink-700 bg-ink-900/50 p-5">
            <h2 className="font-semibold text-slate-100">{section.title}</h2>
            <p className="mt-2 text-sm text-slate-400 leading-relaxed">{section.body}</p>
          </section>
        ))}
      </div>

      <section className="rounded-2xl border border-ink-700 bg-ink-900/50 p-5">
        <h2 className="font-semibold text-slate-100">References</h2>
        <ul className="mt-3 space-y-2 text-sm text-slate-400">
          {references.map(([label, href]) => (
            <li key={href}>
              <a href={href} className="text-accent-400 hover:text-accent-300 transition">
                {label}
              </a>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
