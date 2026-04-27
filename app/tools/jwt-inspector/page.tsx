"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { parseJwt } from "@/lib/jwt/parse";
import { analyzeJwt } from "@/lib/jwt/analyze";
import { crackHmac, isHmacAlg, verifyWithSecret } from "@/lib/jwt/crack";
import { FindingsList } from "@/components/FindingsList";
import { JsonView } from "@/components/JsonView";

const SAMPLES: { label: string; jwt: string; note: string }[] = [
  {
    label: "HS256 / secret = \"secret\"",
    jwt: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsImFkbWluIjp0cnVlLCJpYXQiOjE3MDAwMDAwMDB9.4y5kKdwW5SrcJAR2hO3ws9TKS22N0zoRRQYLsR_kHfw",
    note: "Signed with the classic weak secret \"secret\". Try the cracker.",
  },
  {
    label: "jwt.io demo token",
    jwt: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    note: "Signed with \"your-256-bit-secret\". Also in the wordlist.",
  },
  {
    label: "alg: none (forged)",
    jwt: "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhbGljZSIsImFkbWluIjp0cnVlLCJpYXQiOjE3MDAwMDAwMDB9.",
    note: "No signature. Some libraries used to honour this header and accept anything.",
  },
];

type Coloured = "header" | "payload" | "signature";
const COLOURS: Record<Coloured, string> = {
  header: "text-rose-400",
  payload: "text-fuchsia-400",
  signature: "text-sky-400",
};

function ColouredJwt({ raw }: { raw: string }) {
  const parts = raw.split(".");
  return (
    <div className="font-mono text-xs leading-relaxed break-all bg-ink-950/70 border border-ink-700/70 rounded-lg p-3">
      {parts.map((part, i) => {
        const kind: Coloured = i === 0 ? "header" : i === 1 ? "payload" : "signature";
        return (
          <span key={i}>
            {i > 0 && <span className="text-slate-600">.</span>}
            <span className={COLOURS[kind]}>{part}</span>
          </span>
        );
      })}
    </div>
  );
}

export default function JwtInspectorPage() {
  const [input, setInput] = useState("");
  const [secret, setSecret] = useState("");
  const [verifyState, setVerifyState] = useState<
    | { kind: "idle" }
    | { kind: "checking" }
    | { kind: "result"; ok: boolean; reason?: string }
  >({ kind: "idle" });
  const [crackState, setCrackState] = useState<
    | { kind: "idle" }
    | { kind: "running"; tried: number; total: number }
    | { kind: "done"; secret: string | null; tried: number; durationMs: number }
    | { kind: "error"; message: string }
  >({ kind: "idle" });
  const wordlistRef = useRef<string[] | null>(null);

  const parsed = useMemo(() => parseJwt(input), [input]);
  const findings = useMemo(() => (parsed.ok ? analyzeJwt(parsed.jwt) : []), [parsed]);
  const alg = parsed.ok ? (parsed.jwt.header as { alg?: unknown }).alg : undefined;
  const showHmacTools = parsed.ok && isHmacAlg(alg);

  useEffect(() => {
    setVerifyState({ kind: "idle" });
    setCrackState({ kind: "idle" });
  }, [input]);

  async function loadWordlist(): Promise<string[]> {
    if (wordlistRef.current) return wordlistRef.current;
    const res = await fetch("/jwt-wordlist.json");
    if (!res.ok) throw new Error(`Failed to fetch wordlist (${res.status}).`);
    const list = (await res.json()) as string[];
    wordlistRef.current = list;
    return list;
  }

  async function onVerify() {
    if (!parsed.ok) return;
    setVerifyState({ kind: "checking" });
    const r = await verifyWithSecret(parsed.jwt, secret);
    setVerifyState({ kind: "result", ok: r.verified, reason: r.reason });
  }

  async function onCrack() {
    if (!parsed.ok) return;
    try {
      const list = await loadWordlist();
      setCrackState({ kind: "running", tried: 0, total: list.length });
      const result = await crackHmac(parsed.jwt, list, (tried) =>
        setCrackState({ kind: "running", tried, total: list.length }),
      );
      setCrackState({
        kind: "done",
        secret: result.secret,
        tried: result.tried,
        durationMs: result.durationMs,
      });
    } catch (e) {
      setCrackState({ kind: "error", message: e instanceof Error ? e.message : "crack failed" });
    }
  }

  return (
    <div className="space-y-8">
      <header>
        <p className="text-xs uppercase tracking-widest text-accent-400/80">
          Tool · OWASP A02 — Cryptographic Failures
        </p>
        <h1 className="text-3xl md:text-4xl font-bold tracking-tight mt-1">JWT Inspector</h1>
        <p className="mt-3 text-slate-400 max-w-2xl leading-relaxed">
          Decode and audit JSON Web Tokens. Everything happens in your browser — your tokens never
          leave the page. Verifies HMAC signatures, flags common misuses (alg:none, kid injection,
          long lifetimes, sensitive claims), and tries a small list of common secrets.
        </p>
      </header>

      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className="text-slate-500 mr-2">Try a sample:</span>
        {SAMPLES.map((s) => (
          <button
            key={s.label}
            type="button"
            onClick={() => setInput(s.jwt)}
            className="rounded-full border border-ink-600 bg-ink-800/60 hover:border-accent-500/50 hover:text-accent-400 px-3 py-1 transition"
            title={s.note}
          >
            {s.label}
          </button>
        ))}
        {input && (
          <button
            type="button"
            onClick={() => setInput("")}
            className="rounded-full border border-ink-700 bg-ink-900/60 hover:border-rose-500/40 hover:text-rose-300 px-3 py-1 transition ml-auto"
          >
            Clear
          </button>
        )}
      </div>

      <textarea
        value={input}
        onChange={(e) => setInput(e.target.value)}
        placeholder="Paste a JWT (eyJ…)"
        spellCheck={false}
        autoComplete="off"
        rows={4}
        className="w-full rounded-2xl border border-ink-700 bg-ink-900/60 px-4 py-3 font-mono text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-accent-500/60 resize-y"
      />

      {input && !parsed.ok && (
        <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
          {parsed.reason}
        </div>
      )}

      {parsed.ok && (
        <>
          <ColouredJwt raw={parsed.jwt.segments.raw} />

          <div className="grid gap-4 md:grid-cols-3">
            <section className="rounded-2xl border border-rose-500/30 bg-ink-900/40 p-4">
              <h2 className="text-xs font-semibold uppercase tracking-wider text-rose-300 mb-2">
                Header
              </h2>
              <JsonView value={parsed.jwt.header} />
            </section>
            <section className="rounded-2xl border border-fuchsia-500/30 bg-ink-900/40 p-4">
              <h2 className="text-xs font-semibold uppercase tracking-wider text-fuchsia-300 mb-2">
                Payload
              </h2>
              <JsonView value={parsed.jwt.payload} />
            </section>
            <section className="rounded-2xl border border-sky-500/30 bg-ink-900/40 p-4">
              <h2 className="text-xs font-semibold uppercase tracking-wider text-sky-300 mb-2">
                Signature
              </h2>
              <p className="text-xs text-slate-400">
                {parsed.jwt.hasSignature
                  ? `${parsed.jwt.signatureBytes.byteLength} bytes`
                  : "(no signature)"}
              </p>
              <pre className="mt-2 text-xs font-mono text-slate-300 whitespace-pre-wrap break-all">
                {parsed.jwt.segments.signatureB64 || "—"}
              </pre>
            </section>
          </div>

          {showHmacTools && (
            <section className="rounded-2xl border border-ink-700 bg-ink-900/40 p-5 space-y-5">
              <div>
                <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
                  Verify with secret
                </h2>
                <p className="text-xs text-slate-500 mt-1">
                  HMAC verification uses the browser&apos;s Web Crypto API.
                </p>
                <div className="mt-3 flex flex-col sm:flex-row gap-2">
                  <input
                    type="text"
                    value={secret}
                    onChange={(e) => setSecret(e.target.value)}
                    placeholder="HS256 secret"
                    spellCheck={false}
                    autoComplete="off"
                    className="flex-1 rounded-xl border border-ink-700 bg-ink-950/60 px-3 py-2 font-mono text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-accent-500/60"
                  />
                  <button
                    type="button"
                    onClick={onVerify}
                    disabled={verifyState.kind === "checking"}
                    className="rounded-xl bg-accent-500 hover:bg-accent-400 disabled:opacity-50 text-ink-950 font-semibold px-4 py-2 transition"
                  >
                    {verifyState.kind === "checking" ? "Verifying…" : "Verify"}
                  </button>
                </div>
                {verifyState.kind === "result" && (
                  <p
                    className={`mt-3 text-sm ${
                      verifyState.ok ? "text-emerald-300" : "text-rose-300"
                    }`}
                  >
                    {verifyState.ok
                      ? "✓ Signature is valid for this secret."
                      : verifyState.reason ?? "✗ Signature does not match."}
                  </p>
                )}
              </div>

              <hr className="border-ink-700" />

              <div>
                <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
                  Try common secrets
                </h2>
                <p className="text-xs text-slate-500 mt-1">
                  Loads a small wordlist (~100 entries) and HMAC-verifies the token against each
                  one in the browser. Useful for catching dev/test secrets that shipped to prod.
                </p>
                <button
                  type="button"
                  onClick={onCrack}
                  disabled={crackState.kind === "running"}
                  className="mt-3 rounded-xl border border-ink-600 bg-ink-800/60 hover:border-accent-500/50 hover:text-accent-400 disabled:opacity-50 px-4 py-2 text-sm font-semibold transition"
                >
                  {crackState.kind === "running" ? "Trying…" : "Try common secrets"}
                </button>

                {crackState.kind === "running" && (
                  <p className="mt-3 text-xs text-slate-400 font-mono">
                    {crackState.tried} / {crackState.total} candidates…
                  </p>
                )}
                {crackState.kind === "done" && crackState.secret !== null && (
                  <div className="mt-3 rounded-xl border border-rose-500/40 bg-rose-500/10 px-3 py-2">
                    <p className="text-rose-200 text-sm font-semibold">Secret found!</p>
                    <p className="text-xs text-rose-200/80 mt-1">
                      The token was signed with{" "}
                      <code className="font-mono bg-ink-950/60 px-1 rounded">
                        {crackState.secret === "" ? '"" (empty string)' : crackState.secret}
                      </code>
                      . Tried {crackState.tried} candidate(s) in {crackState.durationMs} ms.
                    </p>
                  </div>
                )}
                {crackState.kind === "done" && crackState.secret === null && (
                  <p className="mt-3 text-sm text-slate-400">
                    No match in the small built-in wordlist. (Tried {crackState.tried} in{" "}
                    {crackState.durationMs} ms — this doesn&apos;t mean the secret is strong.)
                  </p>
                )}
                {crackState.kind === "error" && (
                  <p className="mt-3 text-sm text-rose-300">{crackState.message}</p>
                )}
              </div>
            </section>
          )}

          <section className="rounded-2xl border border-ink-700 bg-ink-900/40 p-5">
            <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-300 mb-2">
              Findings
            </h2>
            {findings.length === 0 ? (
              <p className="text-sm text-slate-400">No findings.</p>
            ) : (
              <FindingsList findings={findings} />
            )}
          </section>
        </>
      )}
    </div>
  );
}
