import Link from "next/link";
import type { Tool } from "@/lib/tools/registry";

export function ToolCard({ tool }: { tool: Tool }) {
  const isLive = tool.status === "live";
  const Wrapper: any = isLive ? Link : "div";
  const wrapperProps = isLive ? { href: tool.href } : {};

  return (
    <Wrapper
      {...wrapperProps}
      className={`group relative block rounded-2xl border p-5 transition ${
        isLive
          ? "border-ink-700 bg-ink-900/60 hover:border-accent-500/60 hover:bg-ink-800/80"
          : "border-ink-700/60 bg-ink-900/30 opacity-60 cursor-not-allowed"
      }`}
    >
      <div className="flex items-start justify-between gap-3">
        <div>
          <h3 className="text-lg font-semibold tracking-tight text-slate-100 group-hover:text-accent-400 transition">
            {tool.name}
          </h3>
          <p className="text-sm text-accent-400/80 mt-0.5">{tool.tagline}</p>
        </div>
        <span
          className={`text-[10px] uppercase tracking-wider px-2 py-1 rounded-full border ${
            isLive
              ? "border-emerald-500/40 text-emerald-400 bg-emerald-500/10"
              : "border-slate-600 text-slate-400 bg-slate-800/40"
          }`}
        >
          {isLive ? "Live" : "Soon"}
        </span>
      </div>
      <p className="text-sm text-slate-400 mt-3 leading-relaxed">{tool.description}</p>
      {tool.owaspRefs && (
        <div className="mt-4 flex flex-wrap gap-1.5">
          {tool.owaspRefs.map((ref) => (
            <span
              key={ref}
              className="text-[11px] font-mono text-slate-400 border border-ink-600 bg-ink-800/60 rounded px-1.5 py-0.5"
            >
              {ref}
            </span>
          ))}
        </div>
      )}
    </Wrapper>
  );
}
