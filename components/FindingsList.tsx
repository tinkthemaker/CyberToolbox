import type { Finding } from "@/lib/shared/findings";
import { SeverityBadge } from "./SeverityBadge";

export function FindingsList({ findings }: { findings: Finding[] }) {
  return (
    <ul className="divide-y divide-ink-700/70">
      {findings.map((f) => (
        <li key={f.id} className="py-3 flex flex-col gap-2 sm:flex-row sm:items-start sm:gap-4">
          <div className="flex-shrink-0 w-20">
            <SeverityBadge severity={f.severity} />
          </div>
          <div className="min-w-0 flex-1">
            <p className="text-slate-100 font-medium">{f.name}</p>
            <p className="text-sm text-slate-400 leading-relaxed">{f.detail}</p>
            {f.value && (
              <pre className="mt-2 text-xs font-mono text-slate-300 bg-ink-950/70 border border-ink-700/70 rounded px-2 py-1.5 overflow-x-auto whitespace-pre-wrap break-all">
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
  );
}
