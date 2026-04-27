import type { Finding } from "@/lib/shared/findings";
import type { JwtParsed } from "./parse";

const SENSITIVE_KEY_PATTERNS = [
  /^pass(word)?$/i,
  /secret/i,
  /api[_-]?key/i,
  /token$/i,
  /private[_-]?key/i,
  /ssn/i,
  /credit[_-]?card/i,
  /cvv/i,
];

const STANDARD_ALGS = new Set([
  "HS256", "HS384", "HS512",
  "RS256", "RS384", "RS512",
  "PS256", "PS384", "PS512",
  "ES256", "ES384", "ES512", "ES256K",
  "EdDSA",
  "none",
]);

function asNumber(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}

function fmtUnix(ts: number): string {
  try {
    return new Date(ts * 1000).toISOString();
  } catch {
    return String(ts);
  }
}

export function analyzeJwt(jwt: JwtParsed): Finding[] {
  const findings: Finding[] = [];
  const header = jwt.header as Record<string, unknown>;
  const payload = (typeof jwt.payload === "object" ? jwt.payload : {}) as Record<string, unknown>;
  const alg = typeof header.alg === "string" ? header.alg : undefined;
  const typ = typeof header.typ === "string" ? header.typ : undefined;
  const kid = typeof header.kid === "string" ? header.kid : undefined;
  const jku = typeof header.jku === "string" ? header.jku : undefined;
  const x5u = typeof header.x5u === "string" ? header.x5u : undefined;
  const jwk = header.jwk;
  const now = Math.floor(Date.now() / 1000);

  // alg
  if (!alg) {
    findings.push({
      id: "alg-missing",
      name: "Header alg",
      severity: "fail",
      detail: "Header is missing the 'alg' claim. RFC 7515 requires it.",
      recommendation: "Reject tokens with no alg claim.",
    });
  } else if (alg.toLowerCase() === "none") {
    findings.push({
      id: "alg-none",
      name: "alg: none (CRITICAL)",
      severity: "fail",
      detail:
        "Token claims 'none' as its algorithm — anyone can forge tokens by setting alg=none and stripping the signature. Many libraries used to honour this.",
      value: `alg = "${alg}"`,
      recommendation: "Reject alg=none. Pin an algorithm whitelist on the server (never trust the header).",
    });
  } else if (!STANDARD_ALGS.has(alg)) {
    findings.push({
      id: "alg-nonstandard",
      name: "Non-standard alg",
      severity: "warn",
      detail: `'${alg}' is not a standard JOSE algorithm.`,
      value: `alg = "${alg}"`,
    });
  } else {
    findings.push({
      id: "alg",
      name: `Algorithm: ${alg}`,
      severity: "info",
      detail: alg.startsWith("HS")
        ? "HMAC with shared secret. Verify the server uses a high-entropy secret and pins the algorithm."
        : alg.startsWith("RS") || alg.startsWith("PS") || alg.startsWith("ES") || alg === "EdDSA"
          ? "Asymmetric signature. Verify the server pins the algorithm to prevent HS/RS confusion."
          : "Algorithm recognised.",
    });
  }

  // typ
  if (typ && typ.toUpperCase() !== "JWT") {
    findings.push({
      id: "typ",
      name: "Header typ",
      severity: "info",
      detail: `'typ' is '${typ}', not 'JWT'. May indicate a JOSE token of a different type.`,
    });
  }

  // kid injection
  if (kid !== undefined) {
    const suspicious =
      /\.\.\//.test(kid) || /[;'"`\\]/.test(kid) || /\bunion\b/i.test(kid) || kid.includes("\0") || kid.length > 256;
    if (suspicious) {
      findings.push({
        id: "kid-injection",
        name: "Suspicious kid value",
        severity: "fail",
        detail:
          "kid contains characters often used in path traversal, SQL injection, or command injection probes. Servers that look up keys by kid without sanitising have been exploited this way.",
        value: kid.length > 200 ? kid.slice(0, 200) + "…" : kid,
        recommendation: "Treat kid as opaque; look it up against a strict allow-list, never as a file path or query.",
      });
    }
  }

  // jku / x5u — points at external URL for keys
  if (jku) {
    findings.push({
      id: "jku",
      name: "Header jku present",
      severity: "warn",
      detail:
        "jku tells the verifier where to fetch the public key. If the server trusts arbitrary URLs, an attacker can host a JWKS and have their forged token verified.",
      value: jku,
      recommendation: "Pin jku to an explicit allow-list of trusted origins or ignore the header entirely.",
    });
  }
  if (x5u) {
    findings.push({
      id: "x5u",
      name: "Header x5u present",
      severity: "warn",
      detail: "x5u points at an external X.509 cert URL. Same risk as jku.",
      value: x5u,
      recommendation: "Allow-list the origin or ignore the header.",
    });
  }
  if (jwk) {
    findings.push({
      id: "jwk-embedded",
      name: "Embedded jwk in header",
      severity: "fail",
      detail:
        "Header embeds a public key (jwk). Vulnerable verifiers will use it to verify the token, letting an attacker sign with their own key and present the matching jwk.",
      recommendation: "Never trust an inline jwk. Fetch keys from a server-pinned source.",
    });
  }

  // signature presence
  if (!jwt.hasSignature) {
    findings.push({
      id: "no-signature",
      name: "No signature segment",
      severity: alg && alg.toLowerCase() === "none" ? "info" : "fail",
      detail: "Token has only two segments — there is no signature to verify.",
    });
  }

  // exp
  const exp = asNumber(payload.exp);
  if (exp === undefined) {
    findings.push({
      id: "exp-missing",
      name: "Missing 'exp' claim",
      severity: "warn",
      detail: "Token has no expiry. If the server doesn't enforce one out-of-band, the token is valid forever.",
      recommendation: "Always set 'exp' and validate it on the server.",
    });
  } else if (exp < now) {
    findings.push({
      id: "exp-past",
      name: "Token expired",
      severity: "fail",
      detail: `Expired at ${fmtUnix(exp)} (${now - exp}s ago).`,
      value: `exp = ${exp}`,
    });
  } else {
    findings.push({
      id: "exp-ok",
      name: "Token not expired",
      severity: "pass",
      detail: `Expires at ${fmtUnix(exp)} (in ${exp - now}s).`,
      value: `exp = ${exp}`,
    });
  }

  // iat
  const iat = asNumber(payload.iat);
  if (iat !== undefined && iat > now + 60) {
    findings.push({
      id: "iat-future",
      name: "'iat' in the future",
      severity: "warn",
      detail: `Issued-at is ${iat - now}s in the future. Clock skew or forged token.`,
      value: `iat = ${iat}`,
    });
  }

  // nbf
  const nbf = asNumber(payload.nbf);
  if (nbf !== undefined && nbf > now + 60) {
    findings.push({
      id: "nbf-future",
      name: "'nbf' in the future",
      severity: "info",
      detail: `Not valid until ${fmtUnix(nbf)}.`,
      value: `nbf = ${nbf}`,
    });
  }

  // lifetime
  if (exp !== undefined && iat !== undefined) {
    const lifetime = exp - iat;
    const day = 86400;
    if (lifetime > 30 * day) {
      findings.push({
        id: "lifetime-long",
        name: "Very long token lifetime",
        severity: "warn",
        detail: `Token is valid for ${Math.round(lifetime / day)} days. Long lifetimes amplify the impact of leakage.`,
        recommendation: "Use short access-token lifetimes (minutes) plus refresh tokens.",
      });
    } else if (lifetime > day) {
      findings.push({
        id: "lifetime-day",
        name: "Token lifetime > 24h",
        severity: "info",
        detail: `Token is valid for ~${Math.round(lifetime / 3600)} hours.`,
      });
    }
  }

  // standard claims presence
  const recommendedClaims: { key: string; why: string }[] = [
    { key: "iss", why: "issuer — lets the server pin which IdP issued the token" },
    { key: "aud", why: "audience — lets the server reject tokens minted for a different service" },
    { key: "sub", why: "subject — identifies the principal" },
  ];
  for (const c of recommendedClaims) {
    if (payload[c.key] === undefined) {
      findings.push({
        id: `claim-${c.key}-missing`,
        name: `Missing '${c.key}' claim`,
        severity: "info",
        detail: `No ${c.key} claim — ${c.why}.`,
      });
    }
  }

  // sensitive data in payload
  const leaked: string[] = [];
  for (const key of Object.keys(payload)) {
    if (SENSITIVE_KEY_PATTERNS.some((re) => re.test(key))) leaked.push(key);
  }
  if (leaked.length > 0) {
    findings.push({
      id: "sensitive-claims",
      name: "Sensitive data in payload",
      severity: "fail",
      detail:
        "JWT payloads are base64url-encoded, not encrypted. Anyone with the token can read these fields.",
      value: leaked.join(", "),
      recommendation: "Move secrets to server-side session storage or use JWE if you must transport them.",
    });
  }

  return findings;
}
