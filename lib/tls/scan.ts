import tls, { type DetailedPeerCertificate } from "node:tls";
import { guardUrl } from "@/lib/security/ssrf";
import type { Finding, FindingGroup } from "@/lib/shared/findings";
import type { CertReport, CertSubject, ParsedCert } from "./types";
import { extractSignatureAlgorithm } from "./der";

const CONNECT_TIMEOUT_MS = 7000;

type RawConnectResult = {
  chain: DetailedPeerCertificate[];
  protocol: string | null;
  cipher: { name: string; version?: string; standardName?: string } | undefined;
  authorized: boolean;
  authorizationError?: string;
  hostnameMatchError?: string;
  responseTimeMs: number;
};

function walkChain(root: DetailedPeerCertificate): DetailedPeerCertificate[] {
  const chain: DetailedPeerCertificate[] = [];
  const seen = new Set<string>();
  let current: DetailedPeerCertificate | undefined = root;
  while (current && current.fingerprint256 && !seen.has(current.fingerprint256)) {
    chain.push(current);
    seen.add(current.fingerprint256);
    if (current.issuerCertificate && current.issuerCertificate !== current) {
      current = current.issuerCertificate;
    } else {
      break;
    }
  }
  return chain;
}

type StrictResult = { authorized: true } | { authorized: false; error: string };

function strictConnect(host: string, port: number): Promise<StrictResult> {
  return new Promise((resolve) => {
    let settled = false;
    const socket = tls.connect(
      {
        host,
        port,
        servername: host,
        rejectUnauthorized: true,
        checkServerIdentity: () => undefined,
      },
      () => {
        if (settled) return;
        settled = true;
        socket.end();
        resolve({ authorized: true });
      },
    );
    socket.setTimeout(CONNECT_TIMEOUT_MS, () => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ authorized: false, error: "Handshake timed out." });
    });
    socket.on("error", (err: NodeJS.ErrnoException) => {
      if (settled) return;
      settled = true;
      resolve({ authorized: false, error: err.code ?? err.message });
    });
  });
}

function lenientConnect(host: string, port: number): Promise<RawConnectResult> {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    let settled = false;
    const socket = tls.connect(
      {
        host,
        port,
        servername: host,
        rejectUnauthorized: false,
        ALPNProtocols: ["h2", "http/1.1"],
      },
      () => {
        if (settled) return;
        settled = true;
        const rawCert = socket.getPeerCertificate(true);
        const protocol = socket.getProtocol();
        const cipher = socket.getCipher();
        const hostnameError = tls.checkServerIdentity(host, rawCert) as Error | undefined;
        const chain = walkChain(rawCert);
        socket.end();
        resolve({
          chain,
          protocol,
          cipher,
          authorized: false, // overwritten by strict pass
          hostnameMatchError: hostnameError ? hostnameError.message : undefined,
          responseTimeMs: Date.now() - start,
        });
      },
    );
    socket.setTimeout(CONNECT_TIMEOUT_MS, () => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(new Error(`TLS handshake timed out after ${CONNECT_TIMEOUT_MS}ms.`));
    });
    socket.on("error", (err) => {
      if (settled) return;
      settled = true;
      reject(err);
    });
  });
}

async function tlsInspect(host: string, port: number): Promise<RawConnectResult> {
  const [strict, lenient] = await Promise.all([
    strictConnect(host, port),
    lenientConnect(host, port),
  ]);
  return {
    ...lenient,
    authorized: strict.authorized,
    authorizationError: strict.authorized ? undefined : strict.error,
  };
}

function parseSubject(s: unknown): CertSubject {
  if (!s || typeof s !== "object") return {};
  const o = s as Record<string, unknown>;
  const out: CertSubject = {};
  if (typeof o.CN === "string") out.CN = o.CN;
  if (typeof o.O === "string") out.O = o.O;
  if (typeof o.OU === "string") out.OU = o.OU;
  if (typeof o.C === "string") out.C = o.C;
  if (typeof o.L === "string") out.L = o.L;
  if (typeof o.ST === "string") out.ST = o.ST;
  return out;
}

function parseSans(subjectaltname: string | undefined): string[] {
  if (!subjectaltname) return [];
  return subjectaltname
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.startsWith("DNS:"))
    .map((s) => s.slice(4).trim());
}

function detectKey(cert: DetailedPeerCertificate): { keyType: ParsedCert["keyType"]; bits?: number; curve?: string } {
  const c = cert as DetailedPeerCertificate & {
    asn1Curve?: string;
    nistCurve?: string;
    bits?: number;
    modulus?: string;
  };
  const curve = c.nistCurve ?? c.asn1Curve;
  if (curve) return { keyType: "ec", curve, bits: c.bits };
  if (typeof c.modulus === "string" && c.modulus.length > 0) {
    return { keyType: "rsa", bits: c.bits ?? c.modulus.length * 4 };
  }
  if (typeof c.bits === "number") return { keyType: "unknown", bits: c.bits };
  return { keyType: "unknown" };
}

function parseCert(raw: DetailedPeerCertificate, index: number): ParsedCert {
  const validFrom = new Date(raw.valid_from);
  const validTo = new Date(raw.valid_to);
  const now = Date.now();
  const daysUntilExpiry = Math.floor((validTo.getTime() - now) / 86_400_000);
  const expired = validTo.getTime() < now;
  const notYetValid = validFrom.getTime() > now;
  const subject = parseSubject(raw.subject);
  const issuer = parseSubject(raw.issuer);
  const selfSigned =
    !!subject.CN &&
    subject.CN === issuer.CN &&
    (subject.O ?? "") === (issuer.O ?? "");
  const key = detectKey(raw);
  const sigAlg = raw.raw ? extractSignatureAlgorithm(new Uint8Array(raw.raw)) : undefined;
  return {
    index,
    subject,
    issuer,
    sans: parseSans(raw.subjectaltname),
    validFrom: validFrom.toISOString(),
    validTo: validTo.toISOString(),
    daysUntilExpiry,
    expired,
    notYetValid,
    signatureAlgorithm: sigAlg,
    keyType: key.keyType,
    keyBits: key.bits,
    curve: key.curve,
    serialNumber: raw.serialNumber,
    fingerprintSha256: raw.fingerprint256,
    selfSigned,
  };
}

const STRONG_TLS = new Set(["TLSv1.3", "TLSv1.2"]);
const DEPRECATED_TLS = new Set(["TLSv1.1", "TLSv1", "SSLv3", "SSLv2"]);

function analyse(
  chain: ParsedCert[],
  result: RawConnectResult,
): { groups: FindingGroup[]; hostnameMatches: boolean } {
  const findings: Finding[] = [];
  const leaf = chain[0];
  const hostnameMatches = !result.hostnameMatchError;

  // Validation
  if (!result.authorized) {
    findings.push({
      id: "chain-unauthorized",
      name: "Browser would not trust this chain",
      severity: "fail",
      detail:
        result.authorizationError ??
        "Node could not validate the certificate chain against its CA store.",
      recommendation:
        "Ensure all intermediates are served, and the leaf chains to a publicly trusted root.",
    });
  } else {
    findings.push({
      id: "chain-authorized",
      name: "Chain validates against system trust store",
      severity: "pass",
      detail: "Node accepted the chain end-to-end.",
    });
  }

  // Hostname match
  if (!hostnameMatches) {
    findings.push({
      id: "hostname-mismatch",
      name: "Hostname does not match certificate",
      severity: "fail",
      detail: result.hostnameMatchError ?? "tls.checkServerIdentity rejected the cert for this host.",
      recommendation: "Re-issue the certificate with a SAN that covers the hostname being served.",
    });
  } else {
    findings.push({
      id: "hostname-match",
      name: "Hostname matches certificate",
      severity: "pass",
      detail: "Certificate's SANs cover the hostname.",
    });
  }

  // Validity
  if (leaf) {
    if (leaf.expired) {
      findings.push({
        id: "expired",
        name: "Certificate is expired",
        severity: "fail",
        detail: `Expired on ${leaf.validTo}.`,
        value: `valid_to=${leaf.validTo}`,
      });
    } else if (leaf.notYetValid) {
      findings.push({
        id: "not-yet-valid",
        name: "Certificate is not yet valid",
        severity: "fail",
        detail: `Becomes valid on ${leaf.validFrom}. Likely a clock issue.`,
      });
    } else if (leaf.daysUntilExpiry < 7) {
      findings.push({
        id: "expiring-week",
        name: `Expires in ${leaf.daysUntilExpiry} day(s)`,
        severity: "fail",
        detail: "Certificate is about to expire — renew immediately.",
      });
    } else if (leaf.daysUntilExpiry < 30) {
      findings.push({
        id: "expiring-month",
        name: `Expires in ${leaf.daysUntilExpiry} days`,
        severity: "warn",
        detail: "Renew before expiry. Automate with ACME/Let's Encrypt if not already.",
      });
    } else {
      findings.push({
        id: "expiry-ok",
        name: `Expires in ${leaf.daysUntilExpiry} days`,
        severity: "pass",
        detail: `Valid until ${leaf.validTo}.`,
      });
    }

    // Signature algorithm
    if (leaf.signatureAlgorithm) {
      const sig = leaf.signatureAlgorithm.toLowerCase();
      if (sig.includes("md5") || sig.includes("sha1")) {
        findings.push({
          id: "weak-sig",
          name: "Weak signature algorithm",
          severity: "fail",
          detail: `Leaf certificate is signed with ${leaf.signatureAlgorithm}. SHA-1 and MD5 are broken; modern browsers reject SHA-1-signed leaves.`,
          value: leaf.signatureAlgorithm,
          recommendation: "Re-issue with SHA-256 or stronger.",
        });
      } else {
        findings.push({
          id: "sig-ok",
          name: `Signature: ${leaf.signatureAlgorithm}`,
          severity: "pass",
          detail: "Modern signature algorithm.",
        });
      }
    }

    // Key strength
    if (leaf.keyType === "rsa" && typeof leaf.keyBits === "number") {
      if (leaf.keyBits < 2048) {
        findings.push({
          id: "weak-rsa",
          name: "Weak RSA key size",
          severity: "fail",
          detail: `RSA-${leaf.keyBits} is below modern minimums.`,
          recommendation: "Re-issue with RSA-2048 or use ECDSA P-256.",
        });
      } else {
        findings.push({
          id: "rsa-ok",
          name: `Key: RSA-${leaf.keyBits}`,
          severity: "pass",
          detail: "Adequate key strength.",
        });
      }
    } else if (leaf.keyType === "ec") {
      findings.push({
        id: "ec-key",
        name: `Key: EC ${leaf.curve ?? "(curve unknown)"}`,
        severity: "pass",
        detail: "ECDSA keys provide strong security with smaller sizes.",
      });
    } else if (leaf.keyType === "ed25519" || leaf.keyType === "ed448") {
      findings.push({
        id: "edwards-key",
        name: `Key: ${leaf.keyType.toUpperCase()}`,
        severity: "pass",
        detail: "Modern Edwards-curve key.",
      });
    }

    // Self-signed
    if (leaf.selfSigned && chain.length === 1) {
      findings.push({
        id: "self-signed",
        name: "Self-signed certificate",
        severity: "warn",
        detail:
          "Leaf cert is its own issuer. Fine for internal services, but browsers will not trust it.",
      });
    }

    // SAN coverage
    if (leaf.sans.length === 0) {
      findings.push({
        id: "no-sans",
        name: "No SANs on certificate",
        severity: "fail",
        detail:
          "Certificate has no Subject Alternative Names. Modern browsers require SANs and ignore CN for hostname validation.",
      });
    }
  }

  // Protocol
  if (result.protocol) {
    if (DEPRECATED_TLS.has(result.protocol)) {
      findings.push({
        id: "tls-deprecated",
        name: `Negotiated ${result.protocol}`,
        severity: "fail",
        detail: "Server still supports a deprecated TLS version.",
        recommendation: "Disable TLS 1.0 / 1.1 and SSL 3.0 / 2.0 at the server or load balancer.",
      });
    } else if (STRONG_TLS.has(result.protocol)) {
      findings.push({
        id: "tls-version",
        name: `Negotiated ${result.protocol}`,
        severity: "pass",
        detail: "Modern TLS version.",
      });
    } else {
      findings.push({
        id: "tls-unknown",
        name: `Negotiated ${result.protocol}`,
        severity: "info",
        detail: "Unrecognised protocol string.",
      });
    }
  }

  // Cipher
  if (result.cipher?.name) {
    findings.push({
      id: "cipher",
      name: `Cipher: ${result.cipher.name}`,
      severity: "info",
      detail: result.cipher.standardName
        ? `IANA name: ${result.cipher.standardName}`
        : "Negotiated cipher suite.",
    });
  }

  // Chain length sanity
  if (chain.length === 1 && !leaf.selfSigned) {
    findings.push({
      id: "chain-incomplete",
      name: "Server only sent the leaf certificate",
      severity: "warn",
      detail:
        "No intermediates were sent. Some clients (especially without AIA fetching) will fail to build a chain.",
      recommendation: "Configure the server to send the full intermediate chain.",
    });
  }

  return {
    groups: [{ id: "tls", title: "TLS findings", findings }],
    hostnameMatches,
  };
}

function summarise(groups: FindingGroup[]): CertReport["summary"] {
  let pass = 0,
    warn = 0,
    fail = 0,
    info = 0;
  for (const g of groups) {
    for (const f of g.findings) {
      if (f.severity === "pass") pass++;
      else if (f.severity === "warn") warn++;
      else if (f.severity === "fail") fail++;
      else info++;
    }
  }
  return { pass, warn, fail, info };
}

function parseInputHostPort(input: string): { host: string; port: number } | { error: string } {
  const stripped = input.trim().replace(/^https?:\/\//i, "").replace(/\/.*$/, "");
  if (!stripped) return { error: "Empty input." };
  const colonIdx = stripped.lastIndexOf(":");
  let host = stripped;
  let port = 443;
  if (colonIdx > -1 && !stripped.includes("]")) {
    host = stripped.slice(0, colonIdx);
    const portStr = stripped.slice(colonIdx + 1);
    const portNum = Number(portStr);
    if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
      return { error: `Invalid port '${portStr}'.` };
    }
    port = portNum;
  }
  if (!host) return { error: "Missing hostname." };
  return { host, port };
}

export async function runTlsScan(
  input: string,
): Promise<{ ok: true; report: CertReport } | { ok: false; reason: string }> {
  const parsed = parseInputHostPort(input);
  if ("error" in parsed) return { ok: false, reason: parsed.error };
  const { host, port } = parsed;

  const guard = await guardUrl(`https://${host}:${port}`);
  if (!guard.ok) return { ok: false, reason: guard.reason };

  let connect: RawConnectResult;
  try {
    connect = await tlsInspect(host, port);
  } catch (e) {
    const msg = e instanceof Error ? e.message : "TLS connection failed";
    return { ok: false, reason: `Could not connect: ${msg}` };
  }

  const chain = connect.chain.map((c, i) => parseCert(c, i));
  const { groups, hostnameMatches } = analyse(chain, connect);

  return {
    ok: true,
    report: {
      target: {
        input,
        host,
        port,
        ip: guard.ip,
        protocol: connect.protocol ?? undefined,
        cipherName: connect.cipher?.name,
        cipherVersion: connect.cipher?.version,
        responseTimeMs: connect.responseTimeMs,
      },
      chain,
      authorized: connect.authorized,
      authorizationError: connect.authorizationError,
      hostnameMatches,
      hostnameMatchError: connect.hostnameMatchError,
      groups,
      summary: summarise(groups),
    },
  };
}
