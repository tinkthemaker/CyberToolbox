import type { CertReport, ParsedCert } from "@/lib/tls/types";
import { FindingsList } from "./FindingsList";

function dn(parts: ParsedCert["subject"]): string {
  const out: string[] = [];
  if (parts.CN) out.push(`CN=${parts.CN}`);
  if (parts.O) out.push(`O=${parts.O}`);
  if (parts.OU) out.push(`OU=${parts.OU}`);
  if (parts.C) out.push(`C=${parts.C}`);
  return out.join(", ") || "—";
}

function shortFingerprint(fp: string): string {
  return fp.replace(/:/g, "").slice(0, 16).toLowerCase();
}

function CertCard({ cert, isLeaf }: { cert: ParsedCert; isLeaf: boolean }) {
  const role = isLeaf ? "Leaf" : cert.selfSigned && cert.index > 0 ? "Root" : `Intermediate ${cert.index}`;
  return (
    <div className="rounded-2xl border border-ink-700 bg-ink-900/40 p-5 space-y-3">
      <div className="flex items-center justify-between gap-3">
        <span className="text-[10px] uppercase tracking-wider text-accent-400/80">{role}</span>
        <span className="text-[10px] uppercase tracking-wider text-slate-500 font-mono">
          sha256:{shortFingerprint(cert.fingerprintSha256)}…
        </span>
      </div>
      <div>
        <p className="text-xs uppercase tracking-wider text-slate-500">Subject</p>
        <p className="font-mono text-xs text-slate-200 break-all">{dn(cert.subject)}</p>
      </div>
      <div>
        <p className="text-xs uppercase tracking-wider text-slate-500">Issuer</p>
        <p className="font-mono text-xs text-slate-300 break-all">{dn(cert.issuer)}</p>
      </div>
      {cert.sans.length > 0 && (
        <div>
          <p className="text-xs uppercase tracking-wider text-slate-500">SANs ({cert.sans.length})</p>
          <div className="font-mono text-xs text-slate-300 break-all">
            {cert.sans.slice(0, 8).join(", ")}
            {cert.sans.length > 8 ? `, +${cert.sans.length - 8} more` : ""}
          </div>
        </div>
      )}
      <div className="grid grid-cols-2 gap-3 text-xs">
        <div>
          <p className="uppercase tracking-wider text-slate-500">Valid from</p>
          <p className="font-mono text-slate-300">{cert.validFrom.split("T")[0]}</p>
        </div>
        <div>
          <p className="uppercase tracking-wider text-slate-500">Valid until</p>
          <p
            className={`font-mono ${
              cert.expired
                ? "text-rose-300"
                : cert.daysUntilExpiry < 30
                  ? "text-amber-300"
                  : "text-slate-300"
            }`}
          >
            {cert.validTo.split("T")[0]} ({cert.daysUntilExpiry}d)
          </p>
        </div>
        <div>
          <p className="uppercase tracking-wider text-slate-500">Key</p>
          <p className="font-mono text-slate-300">
            {cert.keyType.toUpperCase()}
            {cert.keyBits ? `-${cert.keyBits}` : ""}
            {cert.curve ? ` (${cert.curve})` : ""}
          </p>
        </div>
        <div>
          <p className="uppercase tracking-wider text-slate-500">Signature</p>
          <p className="font-mono text-slate-300 break-all">
            {cert.signatureAlgorithm ?? "—"}
          </p>
        </div>
      </div>
    </div>
  );
}

export function CertReportView({ report }: { report: CertReport }) {
  const { target, chain, authorized, hostnameMatches, summary, groups } = report;
  return (
    <div className="space-y-6">
      <section className="rounded-2xl border border-ink-700 bg-ink-900/60 p-5">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div className="min-w-0">
            <p className="text-xs uppercase tracking-wider text-slate-500">Target</p>
            <p className="font-mono text-sm text-slate-200">
              {target.host}:{target.port} → {target.ip}
            </p>
            <p className="text-xs text-slate-500 mt-1">
              {target.protocol ?? "?"} · {target.cipherName ?? "?"} · {target.responseTimeMs} ms ·{" "}
              {chain.length} cert{chain.length === 1 ? "" : "s"}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span
              className={`text-[11px] uppercase tracking-wider px-2 py-1 rounded-full border ${
                authorized
                  ? "border-emerald-500/40 text-emerald-300 bg-emerald-500/10"
                  : "border-rose-500/40 text-rose-300 bg-rose-500/10"
              }`}
            >
              {authorized ? "Trusted" : "Not trusted"}
            </span>
            <span
              className={`text-[11px] uppercase tracking-wider px-2 py-1 rounded-full border ${
                hostnameMatches
                  ? "border-emerald-500/40 text-emerald-300 bg-emerald-500/10"
                  : "border-rose-500/40 text-rose-300 bg-rose-500/10"
              }`}
            >
              {hostnameMatches ? "Hostname OK" : "Hostname mismatch"}
            </span>
          </div>
        </div>
        <div className="mt-4 grid grid-cols-3 gap-2 text-center max-w-md">
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
      </section>

      <section>
        <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-300 mb-3">
          Certificate chain
        </h2>
        <div className="grid gap-4 md:grid-cols-2">
          {chain.map((c) => (
            <CertCard key={c.fingerprintSha256} cert={c} isLeaf={c.index === 0} />
          ))}
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
          <FindingsList findings={group.findings} />
        </section>
      ))}
    </div>
  );
}
