import { NextResponse } from "next/server";
import { runTlsScan } from "@/lib/tls/scan";
import { rateLimit, clientKeyFromHeaders } from "@/lib/security/rate-limit";
import { readJsonRequest } from "@/lib/security/request";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 15;

export async function POST(req: Request) {
  const key = clientKeyFromHeaders(new Headers(req.headers));
  const rl = rateLimit(key);
  if (!rl.ok) {
    return NextResponse.json(
      { error: `Rate limit exceeded. Try again in ${rl.retryAfterSec}s.` },
      { status: 429, headers: { "Retry-After": String(rl.retryAfterSec) } },
    );
  }

  const parsed = await readJsonRequest(req);
  if (!parsed.ok) {
    return NextResponse.json({ error: parsed.error }, { status: parsed.status });
  }

  const host = (parsed.value as { host?: unknown })?.host;
  if (typeof host !== "string" || host.length === 0 || host.length > 1024) {
    return NextResponse.json(
      { error: "Provide a 'host' string (e.g. example.com or example.com:443)." },
      { status: 400 },
    );
  }

  const result = await runTlsScan(host);
  if (!result.ok) {
    return NextResponse.json({ error: result.reason }, { status: 400 });
  }
  return NextResponse.json(result.report);
}
