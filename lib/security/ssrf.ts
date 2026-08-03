import dns from "node:dns/promises";
import net from "node:net";
import type { LookupFunction } from "node:net";

const BLOCKED_V4_CIDRS = [
  "0.0.0.0/8",
  "10.0.0.0/8",
  "127.0.0.0/8",
  "169.254.0.0/16",
  "172.16.0.0/12",
  "192.0.0.0/24",
  "192.0.2.0/24",
  "192.168.0.0/16",
  "198.18.0.0/15",
  "198.51.100.0/24",
  "203.0.113.0/24",
  "100.64.0.0/10",
  "224.0.0.0/4",
  "240.0.0.0/4",
  "255.255.255.255/32",
];

export type PinnedAddress = { address: string; family: 4 | 6 };

function ipv4ToInt(ip: string): number {
  const parts = ip.split(".");
  if (parts.length !== 4) return -1;
  let n = 0;
  for (const p of parts) {
    const o = Number(p);
    if (!Number.isInteger(o) || o < 0 || o > 255) return -1;
    n = (n << 8) + o;
  }
  return n >>> 0;
}

function inV4Cidr(ip: string, cidr: string): boolean {
  const [range, bitsStr] = cidr.split("/");
  const bits = Number(bitsStr);
  const ipInt = ipv4ToInt(ip);
  const rangeInt = ipv4ToInt(range);
  if (ipInt < 0 || rangeInt < 0) return false;
  if (bits === 0) return true;
  const mask = (~0 << (32 - bits)) >>> 0;
  return (ipInt & mask) === (rangeInt & mask);
}

function isBlockedV6(addr: string): boolean {
  const lower = addr.toLowerCase();
  if (lower === "::" || lower === "::1") return true;
  if (/^fe[89ab][0-9a-f]:/.test(lower)) return true;
  if (/^f[cd][0-9a-f]{2}:/.test(lower)) return true;
  if (/^2001:db8:/.test(lower)) return true;
  if (lower.startsWith("::ffff:")) {
    const v4 = lower.slice(7);
    if (net.isIP(v4) === 4) return isBlockedV4(v4);
    const mapped = v4.match(/^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (mapped) {
      const high = Number.parseInt(mapped[1], 16);
      const low = Number.parseInt(mapped[2], 16);
      return isBlockedV4(
        `${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`,
      );
    }
  }
  if (/^ff[0-9a-f]{2}:/.test(lower)) return true;
  return false;
}

function isBlockedV4(ip: string): boolean {
  return BLOCKED_V4_CIDRS.some((c) => inV4Cidr(ip, c));
}

export type GuardResult =
  | {
      ok: true;
      url: URL;
      ip: string;
      family: 4 | 6;
      addresses: PinnedAddress[];
    }
  | { ok: false; reason: string };

export function pinnedLookup(
  addresses: PinnedAddress[],
): LookupFunction {
  return (_hostname, options, callback) => {
    const family =
      options.family === "IPv4" ? 4 : options.family === "IPv6" ? 6 : options.family;
    const selected = family
      ? addresses.filter((address) => address.family === family)
      : addresses;
    if (selected.length === 0) {
      callback(
        Object.assign(new Error("No validated address for requested family."), { code: "ENOTFOUND" }),
        "",
        0,
      );
    } else if (options.all) {
      callback(null, selected);
    } else {
      callback(null, selected[0].address, selected[0].family);
    }
  };
}

export async function guardUrl(input: string): Promise<GuardResult> {
  let url: URL;
  try {
    url = new URL(input.trim());
  } catch {
    return { ok: false, reason: "Not a valid URL." };
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return { ok: false, reason: "Only http and https are allowed." };
  }

  const hostname = url.hostname.replace(/^\[|\]$/g, "");
  if (!hostname) return { ok: false, reason: "Missing hostname." };

  const literal = net.isIP(hostname);
  if (literal === 4 && isBlockedV4(hostname)) {
    return { ok: false, reason: `Refusing to scan private/reserved address ${hostname}.` };
  }
  if (literal === 6 && isBlockedV6(hostname)) {
    return { ok: false, reason: `Refusing to scan private/reserved IPv6 address ${hostname}.` };
  }
  if (literal !== 0) {
    const family = literal as 4 | 6;
    return { ok: true, url, ip: hostname, family, addresses: [{ address: hostname, family }] };
  }

  const lowered = hostname.toLowerCase();
  if (lowered === "localhost" || lowered.endsWith(".localhost") || lowered.endsWith(".local")) {
    return { ok: false, reason: "Refusing to scan local hostnames." };
  }

  let addrs: { address: string; family: number }[];
  try {
    addrs = await dns.lookup(hostname, { all: true, verbatim: true });
  } catch {
    return { ok: false, reason: `Could not resolve ${hostname}.` };
  }
  if (addrs.length === 0) return { ok: false, reason: `No DNS records for ${hostname}.` };

  for (const a of addrs) {
    if (a.family === 4 && isBlockedV4(a.address)) {
      return { ok: false, reason: `${hostname} resolves to private/reserved ${a.address}.` };
    }
    if (a.family === 6 && isBlockedV6(a.address)) {
      return { ok: false, reason: `${hostname} resolves to private/reserved ${a.address}.` };
    }
  }

  const first = addrs[0];
  const addresses = addrs.map((a) => ({ address: a.address, family: a.family as 4 | 6 }));
  return { ok: true, url, ip: first.address, family: first.family as 4 | 6, addresses };
}
