import React from "react";

function tokenize(json: string): { text: string; cls: string }[] {
  const tokens: { text: string; cls: string }[] = [];
  const re = /("(?:[^"\\]|\\.)*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|([{}\[\],:])/g;
  let lastIdx = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(json)) !== null) {
    if (m.index > lastIdx) tokens.push({ text: json.slice(lastIdx, m.index), cls: "" });
    if (m[1] && m[2]) {
      tokens.push({ text: m[1], cls: "text-accent-400" });
      tokens.push({ text: m[2], cls: "text-slate-500" });
    } else if (m[1]) {
      tokens.push({ text: m[1], cls: "text-emerald-300" });
    } else if (m[3]) {
      tokens.push({ text: m[3], cls: "text-amber-300" });
    } else if (m[4]) {
      tokens.push({ text: m[4], cls: "text-rose-300" });
    } else if (m[5]) {
      tokens.push({ text: m[5], cls: "text-slate-500" });
    }
    lastIdx = m.index + m[0].length;
  }
  if (lastIdx < json.length) tokens.push({ text: json.slice(lastIdx), cls: "" });
  return tokens;
}

export function JsonView({ value }: { value: unknown }) {
  let text: string;
  try {
    text = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  } catch {
    text = String(value);
  }
  if (typeof value !== "string") {
    const tokens = tokenize(text);
    return (
      <pre className="text-xs font-mono leading-relaxed text-slate-200 whitespace-pre-wrap break-all">
        {tokens.map((t, i) =>
          t.cls ? (
            <span key={i} className={t.cls}>
              {t.text}
            </span>
          ) : (
            <span key={i}>{t.text}</span>
          ),
        )}
      </pre>
    );
  }
  return (
    <pre className="text-xs font-mono leading-relaxed text-slate-300 whitespace-pre-wrap break-all">
      {text}
    </pre>
  );
}
