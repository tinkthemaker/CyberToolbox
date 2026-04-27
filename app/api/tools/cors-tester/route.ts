import { NextResponse } from "next/server";
import { runCorsScan } from "@/lib/cors/scan";
import { rateLimit, clientKeyFromHeaders } from "@/lib/security/rate-limit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 20;

export async function POST(req: Request) {
  const key = clientKeyFromHeaders(new Headers(req.headers));
  const rl = rateLimit(key);
  if (!rl.ok) {
    return NextResponse.json(
      { error: `Rate limit exceeded. Try again in ${rl.retryAfterSec}s.` },
      { status: 429, headers: { "Retry-After": String(rl.retryAfterSec) } },
    );
  }

  let payload: unknown;
  try {
    payload = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  const url = (payload as { url?: unknown })?.url;
  if (typeof url !== "string" || url.length === 0 || url.length > 2048) {
    return NextResponse.json({ error: "Provide a 'url' string (max 2048 chars)." }, { status: 400 });
  }

  const normalised = /^https?:\/\//i.test(url) ? url : `https://${url}`;

  const result = await runCorsScan(normalised);
  if (!result.ok) {
    return NextResponse.json({ error: result.reason }, { status: 400 });
  }
  return NextResponse.json(result.report);
}
