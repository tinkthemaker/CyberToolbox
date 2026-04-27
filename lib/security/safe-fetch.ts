import { guardUrl } from "./ssrf";

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

async function readLimitedText(res: Response, max = MAX_BODY_BYTES): Promise<string> {
  const reader = res.body?.getReader();
  if (!reader) return "";
  const decoder = new TextDecoder();
  let received = 0;
  let out = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    received += value.byteLength;
    out += decoder.decode(value, { stream: true });
    if (received >= max) {
      try {
        await reader.cancel();
      } catch {
        // ignore
      }
      break;
    }
  }
  out += decoder.decode();
  return out;
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

    let res: Response;
    try {
      res = await fetch(guard.url.toString(), {
        ...init,
        headers: {
          "User-Agent": USER_AGENT,
          Accept: "*/*",
          ...(init.headers ?? {}),
        },
        redirect: "manual",
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "fetch failed";
      return { ok: false, reason: `Network error: ${msg}` };
    }

    if (res.status >= 300 && res.status < 400 && res.headers.get("location")) {
      const next = new URL(res.headers.get("location")!, guard.url).toString();
      redirects.push(next);
      current = next;
      try {
        await res.body?.cancel();
      } catch {
        // ignore
      }
      continue;
    }

    const body = await readLimitedText(res);
    return {
      ok: true,
      data: {
        finalUrl: guard.url.toString(),
        status: res.status,
        headers: res.headers,
        body,
        redirects,
        responseTimeMs: Date.now() - start,
      },
    };
  }

  return { ok: false, reason: `Too many redirects (>${MAX_REDIRECTS}).` };
}
