import dns from "node:dns/promises";
import net from "node:net";

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

const BLOCKED_V6_CIDRS = [
  "::/128", // unspecified
  "::1/128", // loopback
  "::ffff:0.0.0.0/96", // IPv4-mapped (including hex-encoded private IPv4)
  "::ffff:0:0:0/96", // IPv4-translatable
  "64:ff9b::/96", // well-known NAT64 translation prefix
  "64:ff9b:1::/48", // local-use NAT64 translation prefix
  "100::/64", // discard-only
  "2001::/32", // Teredo embeds an IPv4 destination
  "2001:db8::/32", // documentation
  "2002::/16", // 6to4 embeds an IPv4 destination
  "fc00::/7", // unique-local
  "fe80::/10", // link-local
  "fec0::/10", // deprecated site-local
  "ff00::/8", // multicast
];

const blockedAddresses = new net.BlockList();
for (const cidr of BLOCKED_V4_CIDRS) {
  const [network, prefix] = cidr.split("/");
  blockedAddresses.addSubnet(network, Number(prefix), "ipv4");
}
for (const cidr of BLOCKED_V6_CIDRS) {
  const [network, prefix] = cidr.split("/");
  blockedAddresses.addSubnet(network, Number(prefix), "ipv6");
}

function unbracketHostname(hostname: string): string {
  return hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname;
}

function isBlockedAddress(address: string, family: 4 | 6): boolean {
  return blockedAddresses.check(address, family === 4 ? "ipv4" : "ipv6");
}

export type GuardResult =
  | { ok: true; url: URL; ip: string; family: 4 | 6 }
  | { ok: false; reason: string };

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

  if (url.username || url.password) {
    return { ok: false, reason: "URLs containing credentials are not allowed." };
  }

  const hostname = unbracketHostname(url.hostname);
  if (!hostname) return { ok: false, reason: "Missing hostname." };

  const literal = net.isIP(hostname);
  if (literal !== 0 && isBlockedAddress(hostname, literal as 4 | 6)) {
    return { ok: false, reason: `Refusing to scan private/reserved address ${hostname}.` };
  }
  if (literal !== 0) {
    return { ok: true, url, ip: hostname, family: literal as 4 | 6 };
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
    if ((a.family === 4 || a.family === 6) && isBlockedAddress(a.address, a.family)) {
      return { ok: false, reason: `${hostname} resolves to private/reserved ${a.address}.` };
    }
  }

  const first = addrs[0];
  if (first.family !== 4 && first.family !== 6) {
    return { ok: false, reason: `Unsupported address family for ${hostname}.` };
  }
  return { ok: true, url, ip: first.address, family: first.family as 4 | 6 };
}
