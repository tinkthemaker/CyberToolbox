import { request as httpRequest } from "node:http";
import type { IncomingMessage } from "node:http";
import { request as httpsRequest, type RequestOptions } from "node:https";
import net from "node:net";
import { guardUrl } from "./ssrf";
import type { GuardResult } from "./ssrf";

export type SafeFetchResult = {
  finalUrl: string;
  status: number;
  headers: Headers;
  body: string;
  redirects: string[];
  responseTimeMs: number;
};

const USER_AGENT = "CyberToolbox/0.1 (+https://github.com/tinkthemaker/CyberToolbox)";
const MAX_REDIRECTS = 3;
const MAX_BODY_BYTES = 256 * 1024;
const TIMEOUT_MS = 6000;

type AllowedGuard = Extract<GuardResult, { ok: true }>;

type PinnedResponse = {
  status: number;
  headers: Headers;
  body: string;
};

function responseHeaders(res: IncomingMessage): Headers {
  const headers = new Headers();
  for (let i = 0; i < res.rawHeaders.length; i += 2) {
    headers.append(res.rawHeaders[i], res.rawHeaders[i + 1]);
  }
  return headers;
}

function readLimitedText(res: IncomingMessage, max = MAX_BODY_BYTES): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let received = 0;
    let settled = false;

    const finish = () => {
      if (settled) return;
      settled = true;
      resolve(Buffer.concat(chunks, received).toString("utf8"));
    };

    res.on("data", (value: Buffer | Uint8Array | string) => {
      if (settled) return;
      const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value);
      const remaining = max - received;
      if (remaining > 0) {
        const accepted = chunk.subarray(0, remaining);
        chunks.push(accepted);
        received += accepted.byteLength;
      }
      if (received >= max) {
        finish();
        res.destroy();
      }
    });
    res.on("end", finish);
    res.on("aborted", () => {
      if (!settled) reject(new Error("Response was aborted."));
    });
    res.on("error", (error) => {
      if (!settled) reject(error);
    });
  });
}

function makeRequestHeaders(url: URL, init: RequestInit): Record<string, string> {
  const headers = new Headers(init.headers);
  headers.delete("connection");
  headers.delete("content-length");
  headers.delete("host");
  headers.delete("transfer-encoding");
  if (!headers.has("user-agent")) headers.set("user-agent", USER_AGENT);
  if (!headers.has("accept")) headers.set("accept", "*/*");
  // Avoid automatic decompression and cap the exact bytes received from the peer.
  headers.set("accept-encoding", "identity");
  headers.set("host", url.host);
  return Object.fromEntries(headers.entries());
}

function pinnedRequest(guard: AllowedGuard, init: RequestInit): Promise<PinnedResponse> {
  return new Promise((resolve, reject) => {
    if (init.body !== undefined && init.body !== null) {
      reject(new Error("Request bodies are not supported by safeFetch."));
      return;
    }

    const url = guard.url;
    const originalHostname = url.hostname.startsWith("[")
      ? url.hostname.slice(1, -1)
      : url.hostname;
    const options: RequestOptions = {
      protocol: url.protocol,
      hostname: guard.ip,
      family: guard.family,
      port: url.port || (url.protocol === "https:" ? 443 : 80),
      method: init.method ?? "GET",
      path: `${url.pathname}${url.search}`,
      headers: makeRequestHeaders(url, init),
      agent: false,
    };
    if (url.protocol === "https:" && net.isIP(originalHostname) === 0) {
      options.servername = originalHostname;
    }

    const request = (url.protocol === "https:" ? httpsRequest : httpRequest)(options, (res) => {
      const headers = responseHeaders(res);
      const status = res.statusCode ?? 0;
      if (status >= 300 && status < 400 && headers.has("location")) {
        resolve({ status, headers, body: "" });
        res.destroy();
        return;
      }
      readLimitedText(res).then(
        (body) => resolve({ status, headers, body }),
        reject,
      );
    });

    const timeout = setTimeout(() => {
      request.destroy(new Error(`Request timed out after ${TIMEOUT_MS}ms.`));
    }, TIMEOUT_MS);
    timeout.unref?.();
    request.on("close", () => clearTimeout(timeout));
    request.on("error", reject);
    request.end();
  });
}

export async function safeFetch(
  inputUrl: string,
  init: RequestInit = {},
): Promise<{ ok: true; data: SafeFetchResult } | { ok: false; reason: string }> {
  let current = inputUrl;
  const redirects: string[] = [];
  const start = Date.now();

  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    const guard = await guardUrl(current);
    if (!guard.ok) return { ok: false, reason: guard.reason };

    let res: PinnedResponse;
    try {
      // Connect to the exact address that passed validation. Re-resolving the
      // hostname here would re-open the SSRF guard to DNS rebinding attacks.
      res = await pinnedRequest(guard, init);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "fetch failed";
      return { ok: false, reason: `Network error: ${msg}` };
    }

    if (res.status >= 300 && res.status < 400 && res.headers.get("location")) {
      const next = new URL(res.headers.get("location")!, guard.url).toString();
      redirects.push(next);
      current = next;
      continue;
    }

    return {
      ok: true,
      data: {
        finalUrl: guard.url.toString(),
        status: res.status,
        headers: res.headers,
        body: res.body,
        redirects,
        responseTimeMs: Date.now() - start,
      },
    };
  }

  return { ok: false, reason: `Too many redirects (>${MAX_REDIRECTS}).` };
}
