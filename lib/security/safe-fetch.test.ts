import { EventEmitter } from "node:events";
import type { ClientRequest, IncomingMessage } from "node:http";
import type { RequestOptions } from "node:https";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  guardUrl: vi.fn(),
  pinnedLookup: vi.fn(),
  lookup: vi.fn(),
  httpRequest: vi.fn(),
  httpsRequest: vi.fn(),
}));

vi.mock("./ssrf", () => ({
  guardUrl: mocks.guardUrl,
  pinnedLookup: mocks.pinnedLookup,
}));
vi.mock("node:http", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:http")>();
  return {
    ...actual,
    default: { ...actual, request: mocks.httpRequest },
    request: mocks.httpRequest,
  };
});
vi.mock("node:https", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:https")>();
  return {
    ...actual,
    default: { ...actual, request: mocks.httpsRequest },
    request: mocks.httpsRequest,
  };
});

import { safeFetch } from "./safe-fetch";

function successfulRequest(
  _url: URL,
  options: RequestOptions,
  callback: (response: IncomingMessage) => void,
): ClientRequest {
  const request = new EventEmitter();
  Object.assign(request, {
    end: () => {
      const response = new EventEmitter();
      Object.assign(response, {
        statusCode: 200,
        headers: { "content-type": "text/plain" },
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
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.pinnedLookup.mockReturnValue(mocks.lookup);
  });

  it("uses only validated addresses while preserving Host and SNI", async () => {
    const addresses = [{ address: "93.184.216.34", family: 4 }];
    mocks.guardUrl.mockResolvedValue({
      ok: true,
      url: new URL("https://example.com:8443/audit?mode=short"),
      ip: "93.184.216.34",
      family: 4,
      addresses,
    });
    mocks.httpsRequest.mockImplementation(successfulRequest);

    const result = await safeFetch("https://example.com:8443/audit?mode=short");

    expect(result).toMatchObject({ ok: true, data: { status: 200, body: "ok" } });
    expect(mocks.pinnedLookup).toHaveBeenCalledWith(addresses);
    expect(mocks.httpsRequest.mock.calls[0][0]).toEqual(
      new URL("https://example.com:8443/audit?mode=short"),
    );
    const options = mocks.httpsRequest.mock.calls[0][1] as RequestOptions;
    expect(options).toMatchObject({
      servername: "example.com",
      lookup: mocks.lookup,
    });
    expect(options.headers).toMatchObject({
      host: "example.com:8443",
      "accept-encoding": "identity",
    });
  });
});
