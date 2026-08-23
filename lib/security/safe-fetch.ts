import http from "node:http";
import https from "node:https";
import type { IncomingMessage } from "node:http";
import net from "node:net";
import { guardUrl, pinnedLookup } from "./ssrf";

export type SafeFetchInit = {
  method?: string;
  headers?: Record<string, string>;
  deadlineMs?: number;
};

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
      if (chunk.byteLength > remaining) {
        settled = true;
        reject(new Error(`Response body exceeds the ${max} byte limit.`));
        res.destroy();
        return;
      }
      chunks.push(chunk);
      received += chunk.byteLength;
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

function makeRequestHeaders(url: URL, init: SafeFetchInit): Record<string, string> {
  const headers = new Headers(init.headers);
  headers.delete("connection");
  headers.delete("content-length");
  headers.delete("host");
  headers.delete("transfer-encoding");
  if (!headers.has("user-agent")) headers.set("user-agent", USER_AGENT);
  if (!headers.has("accept")) headers.set("accept", "*/*");
  headers.set("accept-encoding", "identity");
  headers.set("host", url.host);
  return Object.fromEntries(headers.entries());
}

export async function safeFetch(
  inputUrl: string,
  init: SafeFetchInit = {},
): Promise<{ ok: true; data: SafeFetchResult } | { ok: false; reason: string }> {
  let current = inputUrl;
  const redirects: string[] = [];
  const start = Date.now();

  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    if (init.deadlineMs !== undefined && init.deadlineMs <= Date.now()) {
      return { ok: false, reason: "Scan time budget exhausted." };
    }
    const guard = await guardUrl(current);
    if (!guard.ok) return { ok: false, reason: guard.reason };
    const remaining = init.deadlineMs === undefined ? TIMEOUT_MS : init.deadlineMs - Date.now();
    if (remaining <= 0) {
      return { ok: false, reason: "Scan time budget exhausted." };
    }

    const timeoutMs = Math.min(TIMEOUT_MS, remaining);
    const headers = makeRequestHeaders(guard.url, init);
    const requestHostname = guard.url.hostname.startsWith("[")
      ? guard.url.hostname.slice(1, -1)
      : guard.url.hostname;
    const requestFn = guard.url.protocol === "https:" ? https.request : http.request;
    const response = await new Promise<
      | { ok: true; status: number; headers: Headers; body: string }
      | { ok: false; reason: string }
    >((resolve) => {
      const req = requestFn(
        guard.url,
        {
          method: init.method ?? "GET",
          headers,
          lookup: pinnedLookup(guard.addresses),
          ...(guard.url.protocol === "https:" && net.isIP(requestHostname) === 0
            ? { servername: requestHostname }
            : {}),
        },
        (res) => {
          const responseHeaders = new Headers();
          for (const [name, value] of Object.entries(res.headers)) {
            if (name === "set-cookie" && Array.isArray(value)) {
              for (const cookie of value) responseHeaders.append(name, cookie);
            } else if (typeof value === "string") {
              responseHeaders.append(name, value);
            } else if (Array.isArray(value)) {
              responseHeaders.append(name, value.join(", "));
            }
          }
          const status = res.statusCode ?? 0;
          if (status >= 300 && status < 400 && responseHeaders.has("location")) {
            clearTimeout(timer);
            resolve({ ok: true, status, headers: responseHeaders, body: "" });
            res.destroy();
            return;
          }
          const body = readLimitedText(res);
          body.then((text) => {
            clearTimeout(timer);
            resolve({
              ok: true,
              status,
              headers: responseHeaders,
              body: text,
            });
          }).catch((error: unknown) => {
            clearTimeout(timer);
            const msg = error instanceof Error ? error.message : "response read failed";
            resolve({ ok: false, reason: `Network error: ${msg}` });
          });
        },
      );
      const timer = setTimeout(() => req.destroy(new Error("Request timed out.")), timeoutMs);
      timer.unref?.();
      req.on("error", (error) => {
        clearTimeout(timer);
        resolve({ ok: false, reason: `Network error: ${error.message}` });
      });
      req.end();
    });
    if (!response.ok) return response;

    if (response.status >= 300 && response.status < 400 && response.headers.get("location")) {
      const next = new URL(response.headers.get("location")!, guard.url).toString();
      redirects.push(next);
      current = next;
      continue;
    }

    return {
      ok: true,
      data: {
        finalUrl: guard.url.toString(),
        status: response.status,
        headers: response.headers,
        body: response.body,
        redirects,
        responseTimeMs: Date.now() - start,
      },
    };
  }

  return { ok: false, reason: `Too many redirects (>${MAX_REDIRECTS}).` };
}
