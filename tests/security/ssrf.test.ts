import dns from "node:dns/promises";
import { afterEach, describe, expect, it, vi } from "vitest";
import { guardUrl } from "@/lib/security/ssrf";

describe("guardUrl", () => {
  afterEach(() => vi.restoreAllMocks());

  it("rejects unsupported schemes", async () => {
    await expect(guardUrl("ftp://example.com")).resolves.toEqual({
      ok: false,
      reason: "Only http and https are allowed.",
    });
  });

  it.each([
    "127.0.0.1",
    "10.1.2.3",
    "169.254.169.254",
    "100.64.1.2",
    "255.255.255.255",
  ])("rejects blocked IPv4 literal %s", async (host) => {
    await expect(guardUrl(`https://${host}`)).resolves.toMatchObject({ ok: false });
  });

  it("allows a public IPv4 literal and returns its address", async () => {
    await expect(guardUrl("https://8.8.8.8")).resolves.toMatchObject({
      ok: true,
      ip: "8.8.8.8",
      family: 4,
      addresses: [{ address: "8.8.8.8", family: 4 }],
    });
  });

  it.each(["::1", "fe80::1", "fc00::1", "ff02::1", "::ffff:127.0.0.1", "2001:db8::1"])(
    "rejects blocked IPv6 literal %s",
    async (host) => {
      await expect(guardUrl(`https://[${host}]`)).resolves.toMatchObject({ ok: false });
    },
  );

  it("allows a public IPv6 literal", async () => {
    await expect(guardUrl("https://[2001:4860:4860::8888]")).resolves.toMatchObject({
      ok: true,
      family: 6,
      addresses: [{ address: "2001:4860:4860::8888", family: 6 }],
    });
  });

  it.each(["localhost", "api.localhost", "service.local"])("rejects local hostname %s", async (host) => {
    await expect(guardUrl(`https://${host}`)).resolves.toMatchObject({ ok: false });
  });

  it("allows all-public DNS answers and returns every address", async () => {
    vi.spyOn(dns, "lookup").mockResolvedValue([
      { address: "93.184.216.34", family: 4 },
      { address: "2001:4860:4860::8888", family: 6 },
    ] as never);
    await expect(guardUrl("https://example.com")).resolves.toMatchObject({
      ok: true,
      ip: "93.184.216.34",
      addresses: [
        { address: "93.184.216.34", family: 4 },
        { address: "2001:4860:4860::8888", family: 6 },
      ],
    });
  });

  it("rejects a DNS answer containing any private address", async () => {
    vi.spyOn(dns, "lookup").mockResolvedValue([
      { address: "93.184.216.34", family: 4 },
      { address: "10.0.0.5", family: 4 },
    ] as never);
    await expect(guardUrl("https://example.com")).resolves.toMatchObject({ ok: false });
  });

  it("reports DNS resolution failures and empty answers", async () => {
    vi.spyOn(dns, "lookup").mockRejectedValueOnce(new Error("no answer"));
    await expect(guardUrl("https://example.com")).resolves.toMatchObject({
      ok: false,
      reason: "Could not resolve example.com.",
    });

    vi.spyOn(dns, "lookup").mockResolvedValueOnce([] as never);
    await expect(guardUrl("https://example.com")).resolves.toMatchObject({
      ok: false,
      reason: "No DNS records for example.com.",
    });
  });
});
