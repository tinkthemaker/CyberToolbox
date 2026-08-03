function readLength(buf: Uint8Array, offset: number): { length: number; bytesUsed: number } | undefined {
  if (offset < 0 || offset >= buf.length) return undefined;
  const first = buf[offset];
  if ((first & 0x80) === 0) return { length: first, bytesUsed: 1 };
  const numBytes = first & 0x7f;
  if (numBytes === 0 || numBytes > 4 || offset + numBytes >= buf.length) return undefined;
  let length = 0;
  for (let i = 1; i <= numBytes; i++) length = length * 256 + buf[offset + i];
  return { length, bytesUsed: numBytes + 1 };
}

function decodeOid(bytes: Uint8Array): string | undefined {
  if (bytes.length === 0) return undefined;
  const parts: number[] = [];
  const first = Math.min(Math.floor(bytes[0] / 40), 2);
  parts.push(first);
  parts.push(bytes[0] - 40 * first);
  let value = 0;
  for (let i = 1; i < bytes.length; i++) {
    value = value * 128 + (bytes[i] & 0x7f);
    if ((bytes[i] & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }
  return bytes[bytes.length - 1] & 0x80 ? undefined : parts.join(".");
}

const SIG_OID_NAMES: Record<string, string> = {
  "1.2.840.113549.1.1.2": "md2WithRSAEncryption",
  "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
  "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
  "1.2.840.113549.1.1.10": "rsassaPss",
  "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
  "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
  "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
  "1.2.840.10045.4.1": "ecdsa-with-SHA1",
  "1.2.840.10045.4.3.1": "ecdsa-with-SHA224",
  "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
  "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
  "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
  "1.3.101.112": "Ed25519",
  "1.3.101.113": "Ed448",
};

export function extractSignatureAlgorithm(der: Uint8Array): string | undefined {
  try {
    let pos = 0;
    if (der[pos++] !== 0x30) return undefined;
    const outer = readLength(der, pos);
    if (!outer || outer.length > der.length - pos - outer.bytesUsed) return undefined;
    pos += outer.bytesUsed;

    if (der[pos++] !== 0x30) return undefined;
    const tbs = readLength(der, pos);
    if (!tbs || tbs.length > der.length - pos - tbs.bytesUsed) return undefined;
    pos += tbs.bytesUsed + tbs.length;

    if (der[pos++] !== 0x30) return undefined;
    const sigAlg = readLength(der, pos);
    if (!sigAlg || sigAlg.length > der.length - pos - sigAlg.bytesUsed) return undefined;
    pos += sigAlg.bytesUsed;

    if (der[pos++] !== 0x06) return undefined;
    const oid = readLength(der, pos);
    if (!oid || oid.length > der.length - pos - oid.bytesUsed) return undefined;
    pos += oid.bytesUsed;

    const oidStr = decodeOid(der.subarray(pos, pos + oid.length));
    if (!oidStr) return undefined;
    return SIG_OID_NAMES[oidStr] ?? oidStr;
  } catch {
    return undefined;
  }
}
