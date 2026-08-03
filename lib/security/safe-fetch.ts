import http from "node:http";
import https from "node:https";
import type { IncomingMessage } from "node:http";
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

async function readLimitedText(res: IncomingMessage, max = MAX_BODY_BYTES): Promise<string> {
  const chunks: Buffer[] = [];
  let received = 0;
  for await (const chunk of res) {
    if (received < max) {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      const allowed = Math.min(bytes.length, max - received);
      if (allowed > 0) {
        chunks.push(bytes.subarray(0, allowed));
        received += allowed;
      }
      if (received >= max) {
        res.resume();
        break;
      }
    }
  }
  return Buffer.concat(chunks).toString("utf8");
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
    const headers = {
      "User-Agent": USER_AGENT,
      Accept: "*/*",
      ...(init.headers ?? {}),
    };
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
          ...(guard.url.protocol === "https:" ? { servername: guard.url.hostname } : {}),
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
          const body = readLimitedText(res);
          body.then((text) => {
            clearTimeout(timer);
            resolve({
              ok: true,
              status: res.statusCode ?? 0,
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
