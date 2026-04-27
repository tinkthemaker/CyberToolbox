import type { Severity } from "@/lib/misconfig/types";

const STYLES: Record<Severity, string> = {
  pass: "border-emerald-500/40 text-emerald-300 bg-emerald-500/10",
  warn: "border-amber-500/40 text-amber-300 bg-amber-500/10",
  fail: "border-rose-500/40 text-rose-300 bg-rose-500/10",
  info: "border-slate-500/40 text-slate-300 bg-slate-500/10",
};

const LABELS: Record<Severity, string> = {
  pass: "Pass",
  warn: "Warn",
  fail: "Fail",
  info: "Info",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 text-[11px] uppercase tracking-wider font-semibold px-2 py-0.5 rounded-full border ${STYLES[severity]}`}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current opacity-90" />
      {LABELS[severity]}
    </span>
  );
}
