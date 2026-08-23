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

type V6Rule = { prefix: number[]; bits: number; embeddedV4?: boolean };

const BLOCKED_V6_RULES: V6Rule[] = [
  { prefix: [0, 0, 0, 0, 0, 0, 0, 0], bits: 128 }, // :: unspecified
  { prefix: [0, 0, 0, 0, 0, 0, 0, 1], bits: 128 }, // ::1 loopback
  { prefix: [0, 0, 0, 0, 0, 0, 0, 0], bits: 96, embeddedV4: true }, // ::a.b.c.d IPv4-compatible (deprecated)
  { prefix: [0, 0, 0, 0, 0, 0xffff, 0, 0], bits: 96, embeddedV4: true }, // ::ffff:a.b.c.d IPv4-mapped
  { prefix: [0x64, 0xff9b, 0, 0, 0, 0, 0, 0], bits: 96, embeddedV4: true }, // 64:ff9b::/96 NAT64 well-known
  { prefix: [0x64, 0xff9b, 1, 0, 0, 0, 0, 0], bits: 48 }, // 64:ff9b:1::/48 NAT64 local-use
  { prefix: [0x100, 0, 0, 0, 0, 0, 0, 0], bits: 64 }, // 100::/64 discard-only
  { prefix: [0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], bits: 32 }, // 2001:db8::/32 documentation
  { prefix: [0xfc00, 0, 0, 0, 0, 0, 0, 0], bits: 7 }, // fc00::/7 unique-local
  { prefix: [0xfe80, 0, 0, 0, 0, 0, 0, 0], bits: 10 }, // fe80::/10 link-local
  { prefix: [0xff00, 0, 0, 0, 0, 0, 0, 0], bits: 8 }, // ff00::/8 multicast
];

function parseV6(addr: string): number[] | null {
  let s = addr.toLowerCase();
  let v4Words: number[] = [];
  const v4Match = s.match(/^(.*:)((?:\d{1,3}\.){3}\d{1,3})$/);
  if (v4Match) {
    const v4 = ipv4ToInt(v4Match[2]);
    if (v4 < 0) return null;
    v4Words = [(v4 >>> 16) & 0xffff, v4 & 0xffff];
    s = v4Match[1].endsWith("::") ? v4Match[1] : v4Match[1].slice(0, -1);
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const parseGroups = (part: string): number[] | null => {
    if (part === "") return [];
    const groups: number[] = [];
    for (const g of part.split(":")) {
      if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
      groups.push(Number.parseInt(g, 16));
    }
    return groups;
  };
  const head = parseGroups(halves[0]);
  const tail = halves.length === 2 ? parseGroups(halves[1]) : null;
  if (head === null || (halves.length === 2 && tail === null)) return null;
  if (halves.length === 1) {
    const words = [...head, ...v4Words];
    return words.length === 8 ? words : null;
  }
  const end = [...(tail ?? []), ...v4Words];
  const fill = 8 - head.length - end.length;
  if (fill < 0) return null;
  return [...head, ...new Array<number>(fill).fill(0), ...end];
}

function inV6Cidr(words: number[], prefix: number[], bits: number): boolean {
  for (let i = 0; i < 8; i++) {
    const groupBits = Math.min(16, bits - i * 16);
    if (groupBits <= 0) return true;
    const mask = groupBits >= 16 ? 0xffff : (0xffff << (16 - groupBits)) & 0xffff;
    if ((words[i] & mask) !== (prefix[i] & mask)) return false;
  }
  return true;
}

function embeddedV4(words: number[]): string {
  return `${words[6] >> 8}.${words[6] & 255}.${words[7] >> 8}.${words[7] & 255}`;
}

function isBlockedV6(addr: string): boolean {
  const words = parseV6(addr);
  if (words === null) return true;
  for (const rule of BLOCKED_V6_RULES) {
    if (inV6Cidr(words, rule.prefix, rule.bits)) {
      return rule.embeddedV4 ? isBlockedV4(embeddedV4(words)) : true;
    }
  }
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
