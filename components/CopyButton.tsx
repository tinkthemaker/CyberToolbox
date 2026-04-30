"use client";

import { useState } from "react";

export function CopyButton({
  value,
  label = "Copy",
  className = "",
}: {
  value: string;
  label?: string;
  className?: string;
}) {
  const [copied, setCopied] = useState(false);

  async function onCopy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      // ignore — older browsers without clipboard API
    }
  }

  return (
    <button
      type="button"
      onClick={onCopy}
      aria-label={`${label} value`}
      className={`text-[10px] uppercase tracking-wider px-2 py-0.5 rounded border border-ink-600 bg-ink-800/60 text-slate-400 hover:border-accent-500/50 hover:text-accent-400 transition focus:outline-none focus:ring-2 focus:ring-accent-500/50 ${className}`}
    >
      {copied ? "Copied" : label}
    </button>
  );
}
