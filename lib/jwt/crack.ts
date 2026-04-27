import { base64UrlDecodeToBytes } from "./parse";
import type { JwtParsed } from "./parse";

const HASH_BY_ALG: Record<string, string> = {
  HS256: "SHA-256",
  HS384: "SHA-384",
  HS512: "SHA-512",
};

export function isHmacAlg(alg: unknown): alg is "HS256" | "HS384" | "HS512" {
  return typeof alg === "string" && alg in HASH_BY_ALG;
}

async function verifyHmac(
  alg: "HS256" | "HS384" | "HS512",
  secret: string,
  signingInput: string,
  signature: Uint8Array,
): Promise<boolean> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: HASH_BY_ALG[alg] },
    false,
    ["verify"],
  );
  return crypto.subtle.verify("HMAC", key, signature, new TextEncoder().encode(signingInput));
}

export async function verifyWithSecret(
  jwt: JwtParsed,
  secret: string,
): Promise<{ verified: boolean; reason?: string }> {
  const alg = (jwt.header as { alg?: unknown }).alg;
  if (!isHmacAlg(alg)) {
    return { verified: false, reason: `verifyWithSecret only supports HS256/HS384/HS512 (alg=${String(alg)}).` };
  }
  if (!jwt.hasSignature) return { verified: false, reason: "Token has no signature segment." };
  try {
    const sig = base64UrlDecodeToBytes(jwt.segments.signatureB64);
    const ok = await verifyHmac(alg, secret, jwt.segments.signingInput, sig);
    return { verified: ok };
  } catch (e) {
    return { verified: false, reason: e instanceof Error ? e.message : "verify failed" };
  }
}

export type CrackResult = { tried: number; secret: string | null; durationMs: number };

export async function crackHmac(
  jwt: JwtParsed,
  wordlist: string[],
  onProgress?: (tried: number) => void,
): Promise<CrackResult> {
  const start =
    typeof performance !== "undefined" && typeof performance.now === "function"
      ? performance.now()
      : Date.now();
  const alg = (jwt.header as { alg?: unknown }).alg;
  if (!isHmacAlg(alg) || !jwt.hasSignature) {
    return { tried: 0, secret: null, durationMs: 0 };
  }
  const sig = base64UrlDecodeToBytes(jwt.segments.signatureB64);
  let tried = 0;
  for (const candidate of wordlist) {
    tried += 1;
    try {
      const ok = await verifyHmac(alg, candidate, jwt.segments.signingInput, sig);
      if (ok) {
        const end =
          typeof performance !== "undefined" && typeof performance.now === "function"
            ? performance.now()
            : Date.now();
        return { tried, secret: candidate, durationMs: Math.round(end - start) };
      }
    } catch {
      // ignore individual candidate errors
    }
    if (onProgress && tried % 25 === 0) onProgress(tried);
  }
  const end =
    typeof performance !== "undefined" && typeof performance.now === "function"
      ? performance.now()
      : Date.now();
  return { tried, secret: null, durationMs: Math.round(end - start) };
}
