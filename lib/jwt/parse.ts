export type JwtSegments = {
  raw: string;
  headerB64: string;
  payloadB64: string;
  signatureB64: string;
  signingInput: string;
};

export type JwtParsed = {
  segments: JwtSegments;
  header: Record<string, unknown>;
  payload: Record<string, unknown> | string;
  signatureBytes: Uint8Array;
  hasSignature: boolean;
};

export type ParseResult =
  | { ok: true; jwt: JwtParsed }
  | { ok: false; reason: string };

export function base64UrlDecodeToBytes(input: string): Uint8Array {
  const pad = input.length % 4 === 0 ? "" : "=".repeat(4 - (input.length % 4));
  const b64 = input.replace(/-/g, "+").replace(/_/g, "/") + pad;
  if (typeof atob === "function") {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  return Uint8Array.from(Buffer.from(b64, "base64"));
}

function bytesToUtf8(bytes: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}

export function parseJwt(input: string): ParseResult {
  const trimmed = input.trim().replace(/^Bearer\s+/i, "");
  if (!trimmed) return { ok: false, reason: "Empty input." };
  if (!/^[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+(\.[A-Za-z0-9_\-]*)?$/.test(trimmed)) {
    return { ok: false, reason: "Not a well-formed JWT (expected base64url segments)." };
  }
  const parts = trimmed.split(".");
  const [headerB64, payloadB64, signatureB64 = ""] = parts;

  let header: Record<string, unknown>;
  try {
    header = JSON.parse(bytesToUtf8(base64UrlDecodeToBytes(headerB64)));
  } catch {
    return { ok: false, reason: "Header is not valid base64url-encoded JSON." };
  }
  if (!header || typeof header !== "object" || Array.isArray(header)) {
    return { ok: false, reason: "Header did not decode to a JSON object." };
  }

  let payload: Record<string, unknown> | string;
  try {
    const text = bytesToUtf8(base64UrlDecodeToBytes(payloadB64));
    try {
      payload = JSON.parse(text);
      if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
        payload = text;
      }
    } catch {
      payload = text;
    }
  } catch {
    return { ok: false, reason: "Payload is not valid base64url." };
  }

  let signatureBytes: Uint8Array;
  try {
    signatureBytes = signatureB64 ? base64UrlDecodeToBytes(signatureB64) : new Uint8Array();
  } catch {
    return { ok: false, reason: "Signature is not valid base64url." };
  }

  return {
    ok: true,
    jwt: {
      segments: {
        raw: trimmed,
        headerB64,
        payloadB64,
        signatureB64,
        signingInput: `${headerB64}.${payloadB64}`,
      },
      header,
      payload,
      signatureBytes,
      hasSignature: signatureB64.length > 0,
    },
  };
}
