import { EventEmitter } from "node:events";
import type { ClientRequest, IncomingMessage } from "node:http";
import type { RequestOptions } from "node:https";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  guardUrl: vi.fn(),
  httpRequest: vi.fn(),
  httpsRequest: vi.fn(),
}));

vi.mock("./ssrf", () => ({ guardUrl: mocks.guardUrl }));
vi.mock("node:http", async (importOriginal) => ({
  ...(await importOriginal<typeof import("node:http")>()),
  request: mocks.httpRequest,
}));
vi.mock("node:https", async (importOriginal) => ({
  ...(await importOriginal<typeof import("node:https")>()),
  request: mocks.httpsRequest,
}));

import { safeFetch } from "./safe-fetch";

function successfulRequest(
  options: RequestOptions,
  callback: (response: IncomingMessage) => void,
): ClientRequest {
  const request = new EventEmitter();
  Object.assign(request, {
    end: () => {
      const response = new EventEmitter();
      Object.assign(response, {
        statusCode: 200,
        rawHeaders: ["Content-Type", "text/plain"],
        destroy: vi.fn(),
      });
      callback(response as IncomingMessage);
      queueMicrotask(() => {
        response.emit("data", Buffer.from("ok"));
        response.emit("end");
        request.emit("close");
      });
    },
    destroy: (error?: Error) => {
      if (error) request.emit("error", error);
      request.emit("close");
    },
  });
  return request as ClientRequest;
}

describe("safeFetch", () => {
  beforeEach(() => vi.clearAllMocks());

  it("connects to the IP that passed the guard while preserving Host and SNI", async () => {
    mocks.guardUrl.mockResolvedValue({
      ok: true,
      url: new URL("https://example.com:8443/audit?mode=short"),
      ip: "93.184.216.34",
      family: 4,
    });
    mocks.httpsRequest.mockImplementation(successfulRequest);

    const result = await safeFetch("https://example.com:8443/audit?mode=short");

    expect(result).toMatchObject({ ok: true, data: { status: 200, body: "ok" } });
    const options = mocks.httpsRequest.mock.calls[0][0] as RequestOptions;
    expect(options).toMatchObject({
      hostname: "93.184.216.34",
      family: 4,
      port: "8443",
      servername: "example.com",
      path: "/audit?mode=short",
    });
    expect(options.headers).toMatchObject({
      host: "example.com:8443",
      "accept-encoding": "identity",
    });
  });
});
