"use client";

import { useState } from "react";
import { ScanReportView } from "@/components/ScanReportView";
import type { ScanReport } from "@/lib/misconfig/types";

export default function MisconfigMapperPage() {
  const [url, setUrl] = useState("");
  const [report, setReport] = useState<ScanReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setReport(null);
    try {
      const res = await fetch("/api/tools/misconfig-mapper", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error ?? `Request failed (${res.status}).`);
      } else {
        setReport(data as ScanReport);
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
        <p className="text-xs uppercase tracking-widest text-accent-400/80">Tool · OWASP A05</p>
        <h1 className="text-3xl md:text-4xl font-bold tracking-tight mt-1">Misconfig Mapper</h1>
        <p className="mt-3 text-slate-400 max-w-2xl leading-relaxed">
          Enter a public URL. We&apos;ll fetch it server-side, inspect security headers, sniff for
          common file exposures, and grade cookie hygiene. Only scan systems you own or have
          permission to test.
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
          {loading ? "Scanning…" : "Scan"}
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
          <p className="text-sm">Fetching headers and probing common paths…</p>
        </div>
      )}

      {report && <ScanReportView report={report} />}
    </div>
  );
}
