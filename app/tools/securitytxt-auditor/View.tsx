"use client";

import { useState } from "react";
import { SecurityTxtReportView } from "@/components/SecurityTxtReportView";
import type { SecurityTxtReport } from "@/lib/securitytxt/analyze";

const DEMO_REPORT: SecurityTxtReport = {
  target: {
    finalUrl: "https://example.com/.well-known/security.txt",
    location: "well-known",
    status: 200,
    responseTimeMs: 42,
    redirects: [],
  },
  summary: { score: 90, pass: 7, warn: 1, fail: 0, info: 1 },
  fields: {
    Contact: ["mailto:security@example.com"],
    Expires: ["2026-06-01T00:00:00Z"],
    Canonical: ["https://example.com/.well-known/security.txt"],
    Policy: ["https://example.com/security-policy"],
    Encryption: ["https://example.com/pgp-key.txt"],
    "Preferred-Languages": ["en, es"],
  },
  malformedLines: [],
  groups: [
    {
      id: "demo",
      title: "Demo report",
      findings: [
        {
          id: "demo-contact",
          name: "Contact field present",
          severity: "pass",
          detail: "The policy gives researchers a monitored disclosure channel.",
          value: "mailto:security@example.com",
          recommendation: "Keep this inbox monitored and covered by incident response procedures.",
        },
        {
          id: "demo-expires",
          name: "Expires field is current",
          severity: "pass",
          detail: "The policy has a future expiry date, which signals that the disclosure instructions are maintained.",
          value: "2026-06-01T00:00:00Z",
        },
        {
          id: "demo-hiring",
          name: "Hiring not published",
          severity: "info",
          detail: "Hiring is optional. Some programs use it to route security-minded applicants to the right team.",
          recommendation: "Add Hiring: only if there is a stable security hiring page.",
        },
      ],
    },
  ],
};

export default function SecurityTxtAuditorPage() {
  const [url, setUrl] = useState("");
  const [report, setReport] = useState<SecurityTxtReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setReport(null);
    try {
      const res = await fetch("/api/tools/securitytxt-auditor", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error ?? `Request failed (${res.status}).`);
      } else {
        setReport(data as SecurityTxtReport);
      }
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-8">
      <header>
        <p className="text-xs uppercase tracking-widest text-accent-400/80">Tool · RFC 9116</p>
        <h1 className="text-3xl md:text-4xl font-bold tracking-tight mt-1">Security.txt Auditor</h1>
        <p className="mt-3 text-slate-400 max-w-2xl leading-relaxed">
          Check whether a public domain publishes coordinated vulnerability disclosure instructions.
          The auditor looks for the preferred well-known location, required Contact and Expires
          fields, optional program signals, canonical mismatch, and malformed lines.
        </p>
      </header>

      <form
        onSubmit={onSubmit}
        className="flex flex-col sm:flex-row gap-2 rounded-2xl border border-ink-700 bg-ink-900/60 p-2"
      >
        <input
          type="text"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="example.com or https://example.com"
          required
          autoFocus
          spellCheck={false}
          autoComplete="off"
          className="flex-1 bg-transparent px-4 py-3 font-mono text-sm text-slate-100 placeholder-slate-500 focus:outline-none"
        />
        <button
          type="submit"
          disabled={loading || url.trim().length === 0}
          className="rounded-xl bg-accent-500 hover:bg-accent-400 disabled:opacity-50 disabled:cursor-not-allowed text-ink-950 font-semibold px-5 py-3 transition"
        >
          {loading ? "Auditing…" : "Audit"}
        </button>
        <button
          type="button"
          onClick={() => {
            setError(null);
            setReport(DEMO_REPORT);
          }}
          className="rounded-xl border border-ink-600 hover:border-accent-500/70 text-slate-200 font-semibold px-5 py-3 transition"
        >
          Try demo
        </button>
      </form>

      {error && (
        <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
          {error}
        </div>
      )}

      {loading && (
        <div className="rounded-2xl border border-ink-700 bg-ink-900/40 p-10 text-center text-slate-400">
          <div className="inline-block h-6 w-6 rounded-full border-2 border-accent-500/30 border-t-accent-500 animate-spin mb-3" />
          <p className="text-sm">Checking /.well-known/security.txt and /security.txt…</p>
        </div>
      )}

      {report && <SecurityTxtReportView report={report} />}
    </div>
  );
}
