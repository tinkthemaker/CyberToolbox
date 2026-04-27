import type { ScanReport } from "@/lib/misconfig/types";
import { SeverityBadge } from "./SeverityBadge";

function scoreColor(score: number): string {
  if (score >= 80) return "text-emerald-400";
  if (score >= 50) return "text-amber-400";
  return "text-rose-400";
}

export function ScanReportView({ report }: { report: ScanReport }) {
  const { target, summary, groups } = report;
  return (
    <div className="space-y-6">
      <section className="rounded-2xl border border-ink-700 bg-ink-900/60 p-5">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div className="min-w-0">
            <p className="text-xs uppercase tracking-wider text-slate-500">Target</p>
            <p className="font-mono text-sm text-slate-200 truncate" title={target.finalUrl}>
              {target.finalUrl}
            </p>
            <p className="text-xs text-slate-500 mt-1">
              HTTP {target.status} · {target.responseTimeMs} ms
              {target.redirects.length > 0 ? ` · ${target.redirects.length} redirect(s)` : ""}
            </p>
          </div>
          <div className="flex items-center gap-6">
            <div className="text-right">
              <p className="text-xs uppercase tracking-wider text-slate-500">Score</p>
              <p className={`text-3xl font-bold tabular-nums ${scoreColor(summary.score)}`}>
                {summary.score}
              </p>
            </div>
            <div className="grid grid-cols-3 gap-2 text-center">
              <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/5 px-3 py-2">
                <p className="text-emerald-300 text-lg font-semibold">{summary.pass}</p>
                <p className="text-[10px] uppercase tracking-wider text-slate-500">Pass</p>
              </div>
              <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 px-3 py-2">
                <p className="text-amber-300 text-lg font-semibold">{summary.warn}</p>
                <p className="text-[10px] uppercase tracking-wider text-slate-500">Warn</p>
              </div>
              <div className="rounded-lg border border-rose-500/30 bg-rose-500/5 px-3 py-2">
                <p className="text-rose-300 text-lg font-semibold">{summary.fail}</p>
                <p className="text-[10px] uppercase tracking-wider text-slate-500">Fail</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {groups.map((group) => (
        <section
          key={group.id}
          className="rounded-2xl border border-ink-700 bg-ink-900/40 p-5"
        >
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-300 mb-4">
            {group.title}
          </h2>
          <ul className="divide-y divide-ink-700/70">
            {group.findings.map((f) => (
              <li key={f.id} className="py-3 flex flex-col gap-2 sm:flex-row sm:items-start sm:gap-4">
                <div className="flex-shrink-0 w-20">
                  <SeverityBadge severity={f.severity} />
                </div>
                <div className="min-w-0 flex-1">
                  <p className="text-slate-100 font-medium">{f.name}</p>
                  <p className="text-sm text-slate-400 leading-relaxed">{f.detail}</p>
                  {f.value && (
                    <pre className="mt-2 text-xs font-mono text-slate-300 bg-ink-950/70 border border-ink-700/70 rounded px-2 py-1.5 overflow-x-auto">
                      {f.value}
                    </pre>
                  )}
                  {f.recommendation && (
                    <p className="text-xs text-accent-400/90 mt-2">→ {f.recommendation}</p>
                  )}
                </div>
              </li>
            ))}
          </ul>
        </section>
      ))}
    </div>
  );
}
