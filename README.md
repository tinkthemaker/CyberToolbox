# Cyber Toolbox

A growing collection of small, focused web-security tools. Built with Next.js
(App Router) on Vercel, TypeScript, and Tailwind. Each tool is a self-contained
module so the toolbox can grow without restructuring.

## Tools

| Tool | Status | Covers |
| --- | --- | --- |
| Misconfig Mapper | Live | OWASP A05 — security headers, exposed `.git`/`.env`, cookie hygiene, info disclosure |
| JWT Inspector    | Live | OWASP A02 — JWT decoding + audit (alg:none, kid injection, expired/long lifetimes, sensitive claims) and a client-side HS256 weak-secret cracker via Web Crypto |
| CORS Tester      | Live | OWASP A05 — Origin reflection + credentials, `null` origin trust, suffix/prefix/subdomain bypass, scheme downgrade, `Vary: Origin` hygiene |

More tools planned (subdomain hygiene check, JWT inspector, CORS tester, TLS
certificate viewer, etc.).

## Run locally

```bash
npm install
npm run dev
```

Open http://localhost:3000.

## Deploy to Vercel

1. Push this repo to GitHub.
2. Import it at https://vercel.com/new — Next.js is auto-detected.
3. Defaults are fine. The misconfig API route is configured for the Node
   runtime (it needs DNS resolution for the SSRF guard) with a 15s max
   duration — within the free tier.

## Architecture

```
app/
  page.tsx                          # Tool grid (driven by registry)
  tools/<id>/page.tsx               # Tool UI
  api/tools/<id>/route.ts           # Tool API
components/
  ToolCard.tsx                      # Registry card
  SeverityBadge.tsx                 # Pass/Warn/Fail/Info
  ScanReportView.tsx                # Misconfig report renderer
lib/
  tools/registry.ts                 # Single source of truth for tools
  shared/findings.ts                # Generic Finding / Severity types
  security/
    ssrf.ts                         # Block private/loopback/metadata IPs
    safe-fetch.ts                   # Guarded fetch with redirect re-checks
    rate-limit.ts                   # In-memory per-IP limiter
  misconfig/
    scan.ts                         # Orchestrator
    headers.ts | disclosure.ts | cookies.ts | probes.ts
    types.ts
  jwt/
    parse.ts                        # base64url decode → header/payload/signature
    analyze.ts                      # Security findings
    crack.ts                        # Web Crypto HMAC verify + wordlist crack
  cors/
    types.ts                        # ProbeResult / CorsReport
    scan.ts                         # Probe set + analyzer
public/jwt-wordlist.json            # Common dev/test secrets
```

## Adding a new tool

1. Add an entry to `lib/tools/registry.ts`.
2. Create `app/tools/<id>/page.tsx` for the UI.
3. Create `app/api/tools/<id>/route.ts` for server logic. Always go through
   `safeFetch` from `lib/security/safe-fetch.ts` for any user-supplied URL.
4. Apply `rateLimit(...)` at the top of the route handler.

The home grid picks up the new tool automatically.

## Safety notes

- All user-supplied URLs are resolved server-side and rejected if they map to
  loopback, RFC1918, link-local, CGNAT, multicast, broadcast, or the
  `169.254.169.254` cloud-metadata range. IPv6 loopback / ULA / link-local are
  also rejected.
- Redirects are followed manually with the SSRF guard re-applied at every hop.
- Response bodies are capped at 256 KB and requests at 6 s.
- Per-IP rate limit defaults to 12 scans/min. The in-memory map resets on
  cold start; for production traffic swap in Upstash KV or Vercel KV.
- This is a defensive/educational tool. Only scan systems you own or have
  explicit permission to test.

## License

MIT (see `LICENSE` if added).
