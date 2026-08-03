import { describe, expect, it } from "vitest";
import { extractSignatureAlgorithm } from "@/lib/tls/der";

function certificatePrefix(oid: number[]): Uint8Array {
  const sigAlg = [0x30, oid.length + 2, 0x06, oid.length, ...oid];
  const tbs = [0x30, 0x00];
  return new Uint8Array([0x30, tbs.length + sigAlg.length, ...tbs, ...sigAlg]);
}

describe("extractSignatureAlgorithm", () => {
  it("maps known signature OIDs", () => {
    expect(extractSignatureAlgorithm(certificatePrefix([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]))).toBe(
      "sha256WithRSAEncryption",
    );
    expect(extractSignatureAlgorithm(certificatePrefix([0x2b, 0x65, 0x70]))).toBe("Ed25519");
  });

  it("returns unknown OIDs and decodes first arc 2 correctly", () => {
    expect(extractSignatureAlgorithm(certificatePrefix([0x2a, 0x03]))).toBe("1.2.3");
    expect(extractSignatureAlgorithm(certificatePrefix([0x55, 0x04, 0x03]))).toBe("2.5.4.3");
  });

  it.each([
    new Uint8Array([]),
    new Uint8Array([0x30, 0x82, 0x01]),
    new Uint8Array([0x30, 0x80]),
    new Uint8Array([0x30, 0x85, 0, 0, 0, 0, 1]),
    new Uint8Array([0x30, 0x05, 0x30, 0x04, 0x30]),
    certificatePrefix([0x2a, 0x80]),
  ])("returns undefined for malformed DER", (input) => {
    expect(extractSignatureAlgorithm(input)).toBeUndefined();
  });
});
