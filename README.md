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
| TLS / Cert Viewer | Live | OWASP A02 — live TLS handshake, full chain inspection, expiry, hostname match, weak signature/key algorithms, protocol & cipher |

More tools planned (subdomain hygiene check, open-redirect tester, etc.).

## Run locally

```bash
npm install
npm run dev
```

Open http://localhost:3000.

## Deploy to Vercel

1. Push this repo to GitHub.
2. Import it at https://vercel.com/new — Next.js is auto-detected.
3. (Optional but recommended) set the `SITE_URL` env var to your final
   domain (e.g. `https://cybertoolbox.example.com`). It feeds `robots.txt`,
   `sitemap.xml`, and the OG image's metadata. If you skip it, Vercel's
   `VERCEL_URL` is used as a fallback.
4. Defaults are fine. API routes use the Node runtime (needed for DNS
   resolution in the SSRF guard and `node:tls` for the cert viewer) with
   per-route `maxDuration` configured in `vercel.json` — well within the
   free tier.

## Architecture

```
app/
  page.tsx                          # Tool grid (driven by registry)
  not-found.tsx                     # Custom 404 (lists live tools)
  robots.ts | sitemap.ts            # SEO basics, runtime-rendered
  opengraph-image.tsx               # Edge-rendered OG card via ImageResponse
  tools/<id>/
    page.tsx                        # Server shell, exports metadata
    View.tsx                        # Client UI
  api/tools/<id>/route.ts           # Tool API
middleware.ts                       # Per-request CSP nonce
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
  tls/
    types.ts                        # ParsedCert / CertReport
    scan.ts                         # node:tls handshake, chain walk, analysis
public/jwt-wordlist.json            # Common dev/test secrets
vercel.json                         # Function maxDuration + security headers
```

## Vercel deployment config

`vercel.json` sets per-function `maxDuration` and applies static security
headers (HSTS, XFO=DENY, nosniff, Referrer-Policy, Permissions-Policy)
to every response. CSP is set per-request by `middleware.ts` so each
response gets a fresh nonce — no `'unsafe-inline'` for scripts.

Once deployed, point `Misconfig Mapper` at your own production URL and
watch it pass its own checks — satisfying demo loop.

### CSP nonce

`middleware.ts` issues a 128-bit nonce per request, sets the
`Content-Security-Policy` header on both the request and the response,
and Next.js's runtime threads it onto the inline hydration scripts. The
policy is strict by default:

```
script-src 'self' 'nonce-<random>' 'strict-dynamic'
```

Dev mode adds `'unsafe-eval'` for HMR; production does not.

## Adding a new tool

1. Add an entry to `lib/tools/registry.ts`.
2. Create `app/tools/<id>/View.tsx` (`"use client"`) for the UI.
3. Create `app/tools/<id>/page.tsx`:

   ```tsx
   import { toolMetadata } from "@/lib/tools/registry";
   import View from "./View";
   export const metadata = toolMetadata("<id>");
   export default function Page() { return <View />; }
   ```

4. Create `app/api/tools/<id>/route.ts` for server logic. Always go through
   `safeFetch` from `lib/security/safe-fetch.ts` for any user-supplied URL.
5. Apply `rateLimit(...)` at the top of the route handler.

The home grid, sitemap, and OG image all pick up the new tool automatically.

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

## CI

`.github/workflows/ci.yml` runs typecheck, lint, and build on every push
and pull request.

## License

MIT (see `LICENSE` if added).
