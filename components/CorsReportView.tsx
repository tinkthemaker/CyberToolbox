import type { CorsReport, ProbeResult } from "@/lib/cors/types";
import { FindingsList } from "./FindingsList";

function fmt(value: string | undefined): string {
  if (value === undefined) return "—";
  return value.length > 60 ? value.slice(0, 60) + "…" : value;
}

function ProbeRow({ p }: { p: ProbeResult }) {
  const reflected = p.reflectsOrigin;
  const credentialed = p.acac?.toLowerCase() === "true";
  const danger = reflected && credentialed;
  return (
    <tr
      className={`border-t border-ink-700/60 ${
        danger ? "bg-rose-500/10" : reflected ? "bg-amber-500/5" : ""
      }`}
    >
      <td className="px-3 py-2 align-top">
        <div className="text-slate-200 font-medium">{p.label}</div>
        <div className="text-[11px] uppercase tracking-wider text-slate-500">{p.method}</div>
      </td>
      <td className="px-3 py-2 align-top font-mono text-xs text-slate-300 break-all">
        {p.sentOrigin === null ? <span className="text-slate-500">(no Origin)</span> : p.sentOrigin}
      </td>
      <td className="px-3 py-2 align-top font-mono text-xs text-slate-300">
        {p.error ? <span className="text-rose-300">{p.error}</span> : p.status || "—"}
      </td>
      <td className="px-3 py-2 align-top font-mono text-xs text-slate-300 break-all">
        {fmt(p.acao)}
      </td>
      <td className="px-3 py-2 align-top font-mono text-xs">
        <span
          className={
            credentialed ? "text-rose-300" : p.acac ? "text-slate-300" : "text-slate-500"
          }
        >
          {fmt(p.acac)}
        </span>
      </td>
      <td className="px-3 py-2 align-top text-xs">
        {reflected ? (
          <span
            className={`inline-block rounded-full px-2 py-0.5 border ${
              credentialed
                ? "border-rose-500/40 text-rose-300 bg-rose-500/10"
                : "border-amber-500/40 text-amber-300 bg-amber-500/10"
            }`}
          >
            {credentialed ? "Reflected + creds" : "Reflected"}
          </span>
        ) : (
          <span className="text-slate-500">—</span>
        )}
      </td>
    </tr>
  );
}

export function CorsReportView({ report }: { report: CorsReport }) {
  const { target, probes, groups, summary } = report;
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
              HTTP {target.status} · {target.responseTimeMs} ms · {probes.length} probes
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
      </section>

      <section className="rounded-2xl border border-ink-700 bg-ink-900/40 p-0 overflow-hidden">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-300 px-5 py-4 border-b border-ink-700/70">
          Probes
        </h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-[11px] uppercase tracking-wider text-slate-500 bg-ink-950/40">
              <tr>
                <th className="text-left px-3 py-2 font-medium">Probe</th>
                <th className="text-left px-3 py-2 font-medium">Origin sent</th>
                <th className="text-left px-3 py-2 font-medium">Status</th>
                <th className="text-left px-3 py-2 font-medium">ACAO</th>
                <th className="text-left px-3 py-2 font-medium">ACAC</th>
                <th className="text-left px-3 py-2 font-medium">Result</th>
              </tr>
            </thead>
            <tbody>
              {probes.map((p) => (
                <ProbeRow key={p.id} p={p} />
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {groups.map((group) => (
        <section
          key={group.id}
          className="rounded-2xl border border-ink-700 bg-ink-900/40 p-5"
        >
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-300 mb-2">
            {group.title}
          </h2>
          {group.findings.length === 0 ? (
            <p className="text-sm text-slate-400">No findings.</p>
          ) : (
            <FindingsList findings={group.findings} />
          )}
        </section>
      ))}
    </div>
  );
}
