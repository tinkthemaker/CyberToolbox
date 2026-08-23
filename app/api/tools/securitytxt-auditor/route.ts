import { NextResponse } from "next/server";
import { clientKeyFromHeaders, rateLimit } from "@/lib/security/rate-limit";
import { readJsonRequest } from "@/lib/security/request";
import { runSecurityTxtAudit } from "@/lib/securitytxt/scan";

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

  const url = (parsed.value as { url?: unknown })?.url;
  if (typeof url !== "string" || url.length === 0 || url.length > 2048) {
    return NextResponse.json({ error: "Provide a 'url' string (max 2048 chars)." }, { status: 400 });
  }

  const result = await runSecurityTxtAudit(url);
  if (!result.ok) {
    return NextResponse.json({ error: result.reason }, { status: 400 });
  }
  return NextResponse.json(result.report);
}
