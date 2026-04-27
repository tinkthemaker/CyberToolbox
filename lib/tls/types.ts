import type { FindingGroup } from "@/lib/shared/findings";

export type CertSubject = {
  CN?: string;
  O?: string;
  OU?: string;
  C?: string;
  L?: string;
  ST?: string;
};

export type ParsedCert = {
  index: number;
  subject: CertSubject;
  issuer: CertSubject;
  sans: string[];
  validFrom: string;
  validTo: string;
  daysUntilExpiry: number;
  expired: boolean;
  notYetValid: boolean;
  signatureAlgorithm?: string;
  keyType: "rsa" | "ec" | "ed25519" | "ed448" | "dsa" | "unknown";
  keyBits?: number;
  curve?: string;
  serialNumber: string;
  fingerprintSha256: string;
  selfSigned: boolean;
};

export type CertReport = {
  target: {
    input: string;
    host: string;
    port: number;
    ip: string;
    protocol?: string;
    cipherName?: string;
    cipherVersion?: string;
    responseTimeMs: number;
  };
  chain: ParsedCert[];
  authorized: boolean;
  authorizationError?: string;
  hostnameMatches: boolean;
  hostnameMatchError?: string;
  groups: FindingGroup[];
  summary: {
    pass: number;
    warn: number;
    fail: number;
    info: number;
  };
};
