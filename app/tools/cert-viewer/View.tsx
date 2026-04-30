"use client";

import { useState } from "react";
import { CertReportView } from "@/components/CertReportView";
import type { CertReport } from "@/lib/tls/types";

const SAMPLES = ["github.com", "expired.badssl.com", "self-signed.badssl.com", "wrong.host.badssl.com"];

export default function CertViewerPage() {
  const [host, setHost] = useState("");
  const [report, setReport] = useState<CertReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function scan(target: string) {
    setLoading(true);
    setError(null);
    setReport(null);
    try {
      const res = await fetch("/api/tools/cert-viewer", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ host: target }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error ?? `Request failed (${res.status}).`);
      } else {
        setReport(data as CertReport);
      }
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (host.trim()) scan(host.trim());
  }

  return (
    <div className="space-y-8">
      <header>
        <p className="text-xs uppercase tracking-widest text-accent-400/80">
          Tool · OWASP A02 — Cryptographic Failures
        </p>
        <h1 className="text-3xl md:text-4xl font-bold tracking-tight mt-1">TLS / Cert Viewer</h1>
        <p className="mt-3 text-slate-400 max-w-2xl leading-relaxed">
          Opens a TLS handshake to the target, captures the full certificate chain, and grades it:
          chain validation, hostname match, expiry, signature algorithm, key strength, protocol
          version, and cipher.
        </p>
      </header>

      <form
        onSubmit={onSubmit}
        className="flex flex-col sm:flex-row gap-2 rounded-2xl border border-ink-700 bg-ink-900/60 p-2"
      >
        <input
          type="text"
          value={host}
          onChange={(e) => setHost(e.target.value)}
          placeholder="example.com or example.com:8443"
          required
          autoFocus
          spellCheck={false}
          autoComplete="off"
          className="flex-1 bg-transparent px-4 py-3 font-mono text-sm text-slate-100 placeholder-slate-500 focus:outline-none"
        />
        <button
          type="submit"
          disabled={loading || host.trim().length === 0}
          className="rounded-xl bg-accent-500 hover:bg-accent-400 disabled:opacity-50 disabled:cursor-not-allowed text-ink-950 font-semibold px-5 py-3 transition"
        >
          {loading ? "Connecting…" : "Inspect cert"}
        </button>
      </form>

      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className="text-slate-500 mr-2">Try:</span>
        {SAMPLES.map((s) => (
          <button
            key={s}
            type="button"
            onClick={() => {
              setHost(s);
              scan(s);
            }}
            className="rounded-full border border-ink-600 bg-ink-800/60 hover:border-accent-500/50 hover:text-accent-400 px-3 py-1 transition font-mono"
          >
            {s}
          </button>
        ))}
      </div>

      {error && (
        <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
          {error}
        </div>
      )}

      {loading && (
        <div className="rounded-2xl border border-ink-700 bg-ink-900/40 p-10 text-center text-slate-400">
          <div className="inline-block h-6 w-6 rounded-full border-2 border-accent-500/30 border-t-accent-500 animate-spin mb-3" />
          <p className="text-sm">Performing TLS handshake…</p>
        </div>
      )}

      {report && <CertReportView report={report} />}
    </div>
  );
}
