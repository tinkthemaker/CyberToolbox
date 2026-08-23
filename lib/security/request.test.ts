import { describe, expect, it } from "vitest";
import { readJsonRequest } from "./request";

function request(body: string, contentType = "application/json"): Request {
  return new Request("https://example.test/api", {
    method: "POST",
    headers: { "Content-Type": contentType },
    body,
  });
}

describe("readJsonRequest", () => {
  it("accepts a bounded JSON body", async () => {
    await expect(readJsonRequest(request('{"url":"https://example.com"}'))).resolves.toEqual({
      ok: true,
      value: { url: "https://example.com" },
    });
  });

  it("requires a JSON content type", async () => {
    await expect(readJsonRequest(request("url=example.com", "application/x-www-form-urlencoded"))).resolves.toMatchObject({
      ok: false,
      status: 415,
    });
  });

  it("rejects a streamed body that exceeds the byte limit", async () => {
    await expect(readJsonRequest(request(`{"url":"${"a".repeat(64)}"}`), 32)).resolves.toMatchObject({
      ok: false,
      status: 413,
    });
  });

  it("rejects malformed JSON", async () => {
    await expect(readJsonRequest(request("{"))).resolves.toMatchObject({
      ok: false,
      status: 400,
    });
  });
});
