import { describe, expect, it } from "vitest";
import { guardUrl } from "./ssrf";

describe("guardUrl", () => {
  it.each([
    "http://127.0.0.1",
    "http://169.254.169.254/latest/meta-data",
    "http://[::1]",
    "http://[::7f00:1]",
    "http://[::ffff:7f00:1]",
    "http://[::ffff:0:7f00:1]",
    "http://[64:ff9b::7f00:1]",
    "http://[2001:0:4136:e378:8000:63bf:3fff:fdd2]",
    "http://[fc00::1]",
    "http://[fe80::1]",
  ])("blocks private and translated address %s", async (url) => {
    await expect(guardUrl(url)).resolves.toMatchObject({ ok: false });
  });

  it("returns an unbracketed public IPv6 address for connection pinning", async () => {
    await expect(guardUrl("https://[2606:4700:4700::1111]")).resolves.toMatchObject({
      ok: true,
      ip: "2606:4700:4700::1111",
      family: 6,
    });
  });

  it("rejects URL credentials", async () => {
    await expect(guardUrl("https://user:password@93.184.216.34")).resolves.toEqual({
      ok: false,
      reason: "URLs containing credentials are not allowed.",
    });
  });
});
