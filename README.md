# Cyber Toolbox

[![CI](https://github.com/tinkthemaker/CyberToolbox/actions/workflows/ci.yml/badge.svg)](https://github.com/tinkthemaker/CyberToolbox/actions/workflows/ci.yml)
[![Next.js](https://img.shields.io/badge/Next.js-15-black?logo=next.js)](https://nextjs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-3178C6?logo=typescript)](https://typescriptlang.org)
[![Tailwind](https://img.shields.io/badge/Tailwind-3.4+-06B6D4?logo=tailwindcss)](https://tailwindcss.com)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A growing collection of small, focused **web-security tools** — paste a URL,
get a graded report. Built as a portfolio piece around Next.js (App Router)
on Vercel, TypeScript, Tailwind, and a tool-registry architecture so tools
drop in cleanly.

> **Defensive use only.** Each tool refuses to scan private, loopback, or
> cloud-metadata addresses. Only run scans against systems you own or have
> explicit permission to test.

---

## Tools

| Tool | OWASP | What it does |
| --- | --- | --- |
| **Misconfig Mapper** | A05 | Fetches a target URL server-side, grades security headers (CSP, HSTS, XFO, nosniff, Referrer-Policy, Permissions-Policy), probes common file exposures (`.git/HEAD`, `.git/config`, `.env`, `.DS_Store`, `/server-status`), audits cookie hygiene (Secure / HttpOnly / SameSite), and flags information-disclosure headers. |
| **JWT Inspector** | A02 | Decodes a JWT in the browser (tokens never leave your tab), audits the header & payload (`alg:none`, `kid` injection, `jku`/`x5u`, embedded `jwk`, expired/long-lived tokens, missing `iss`/`aud`/`sub`, sensitive payload claims), verifies HMAC signatures via Web Crypto, and runs a built-in wordlist crack for HS256/384/512. |
| **CORS Tester** | A05 | Sends 8 Origin probes — baseline, arbitrary cross-origin, `null`, suffix bypass, prefix bypass, subdomain trust, scheme downgrade, OPTIONS preflight — and grades the response. Flags the dangerous reflection-with-credentials pattern. |
| **TLS / Cert Viewer** | A02 | Two-pass `node:tls` handshake (one strict for the trust verdict, one lenient for the chain). Walks the issuer chain, parses signature algorithm via a tiny built-in DER reader, and grades expiry tiers, hostname match, weak signature/key algorithms, protocol version, and cipher. |
| **Security.txt Auditor** | RFC 9116 | Checks `/.well-known/security.txt` and `/security.txt`, parses disclosure-program fields, validates required Contact and Expires values, flags canonical mismatch, and reports malformed lines. |

More tools planned (DNS/email security checker, CSP analyzer, open-redirect tester,
robots/sitemap auditor, JOSE algorithm confusion exerciser, etc.).

---

## What this demonstrates

- Next.js App Router with server/client route boundaries and strict TypeScript.
- SSRF-aware server-side scanning with redirect re-checks and blocked private address space.
- Defensive API design: input caps, rate limits, bounded probes, and no third-party APIs or secrets.
- Security-specific parsing and grading for JWTs, CORS behavior, TLS certificates, HTTP headers, cookies, exposed files, and RFC 9116 `security.txt` files.
- Reusable finding/report components with evidence, remediation guidance, and severity scoring.
- CI-friendly quality gates: typecheck, lint, test, and production build.

---

## Quick start

```bash
git clone https://github.com/tinkthemaker/CyberToolbox.git
cd CyberToolbox
npm install
npm run dev
# → http://localhost:3000
```

Build & run a production build locally:

```bash
npm run build
npm run start
```

---

## Deploy to Vercel

The repo is configured to run on Vercel **with no env vars required**. The
common path:

1. Push the repo to GitHub (or fork this one).
2. Go to [vercel.com/new](https://vercel.com/new) and import the repo.
   Next.js 16 is auto-detected — leave the build/output settings on default.
3. Click **Deploy**. First build takes ~30 seconds.
4. Visit your `*.vercel.app` URL. All five tools should work immediately.

Optional: set `SITE_URL` in Vercel's environment-variables panel to your final
custom domain (e.g. `https://cybertoolbox.example.com`). It feeds `robots.txt`,
`sitemap.xml`, and the OG image's metadata. If unset, the runtime falls back
to Vercel's `VERCEL_URL`.

### What Vercel does for you (and what's already configured)

| Concern | Handled by |
| --- | --- |
| Function runtimes | Each API route exports `runtime = "nodejs"` (needed for DNS resolution in the SSRF guard and `node:tls` for the cert viewer). |
| Function timeouts | `vercel.json` sets `maxDuration` per route (15 s misconfig + cert + security.txt, 20 s CORS) — well within the free tier's 10–60 s caps. |
| Static security headers | `vercel.json` applies HSTS, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, and `Permissions-Policy` to every response. |
| Per-request CSP nonce | `proxy.ts` issues a fresh 128-bit nonce on every request and sets `Content-Security-Policy: ... script-src 'self' 'nonce-…' 'strict-dynamic' ...`. Next.js threads the nonce onto every inline hydration script automatically. No `'unsafe-inline'` for scripts. |
| Generated OG image | `app/opengraph-image.tsx` renders dynamically via `next/og`'s `ImageResponse`. |
| Nice URLs / 404s | App Router file-based routing + `app/not-found.tsx` listing live tools. |

After deployment, point Misconfig Mapper at your own production URL — it
should pass all the header checks. Satisfying demo loop for interviews.

---

## Environment variables

| Name | Required | Default | Used by |
| --- | --- | --- | --- |
| `SITE_URL` | No | `https://${VERCEL_URL}` (set by Vercel) → `http://localhost:3000` | `app/robots.ts`, `app/sitemap.ts` |
| `VERCEL_URL` | No (auto) | Set by Vercel at runtime | Fallback for `SITE_URL` |

There are no secrets and no third-party APIs — nothing else to configure.

---

## Architecture

```
app/
├─ page.tsx                          # Tool grid (driven by registry)
├─ layout.tsx                        # Root layout, header/footer, metadata template
├─ globals.css                       # Tailwind base + focus ring + skip-link
├─ not-found.tsx                     # Custom 404 (lists live tools)
├─ robots.ts | sitemap.ts            # SEO basics, runtime-rendered
├─ opengraph-image.tsx               # Generated OG card via ImageResponse
├─ about/page.tsx                    # About page
├─ methodology/page.tsx              # Defensive scope, severity, and limitations
├─ tools/<id>/
│  ├─ page.tsx                       # Server shell, exports metadata
│  └─ View.tsx                       # Client UI ("use client")
└─ api/tools/<id>/route.ts           # Tool API (Node runtime)

components/
├─ ToolCard.tsx                      # Registry card on the home grid
├─ SeverityBadge.tsx                 # pass / warn / fail / info pill
├─ FindingsList.tsx                  # Generic findings renderer
├─ ScanReportView.tsx                # Misconfig report
├─ CorsReportView.tsx                # CORS probe matrix + findings
├─ CertReportView.tsx                # TLS chain cards + findings
├─ SecurityTxtReportView.tsx         # RFC 9116 report
├─ JsonView.tsx                      # Coloured JSON for JWT decoded panels
└─ CopyButton.tsx                    # Tiny reusable copy-to-clipboard

lib/
├─ tools/registry.ts                 # SITE constants + Tool[] + toolMetadata()
├─ shared/findings.ts                # Generic Finding / Severity types
├─ security/
│  ├─ ssrf.ts                        # Block private/loopback/metadata IPs
│  ├─ safe-fetch.ts                  # Guarded fetch with redirect re-checks
│  └─ rate-limit.ts                  # In-memory per-IP limiter
├─ misconfig/
│  ├─ scan.ts                        # Orchestrator
│  ├─ headers.ts | disclosure.ts | cookies.ts | probes.ts
│  └─ types.ts
├─ jwt/
│  ├─ parse.ts                       # base64url → header/payload/signature
│  ├─ analyze.ts                     # Security findings
│  └─ crack.ts                       # Web Crypto HMAC verify + wordlist crack
├─ cors/
│  ├─ scan.ts                        # Probe set + analyzer
│  └─ types.ts
├─ securitytxt/
│  ├─ analyze.ts                     # RFC 9116 parser + findings
│  ├─ analyze.test.ts                # Vitest coverage for parser behavior
│  └─ scan.ts                        # well-known/root fetch orchestration
└─ tls/
   ├─ scan.ts                        # node:tls handshake, chain walk, analysis
   ├─ der.ts                         # ASN.1 walker → signature OID
   └─ types.ts

proxy.ts                             # Per-request CSP nonce
public/jwt-wordlist.json             # Common dev/test secrets (~100 entries)
vercel.json                          # Function maxDuration + static headers
.github/workflows/ci.yml             # audit + typecheck + test + lint + build
```

---

## Security model

### SSRF guard (`lib/security/ssrf.ts`)

Every user-supplied URL goes through `guardUrl(input)` before any outbound
network call:

1. URL parses cleanly and uses `http:` or `https:`.
2. Hostname resolves via `dns.lookup({ all: true })`.
3. Every resolved address is checked against blocklists:
   - **IPv4 CIDRs**: `0.0.0.0/8`, `10.0.0.0/8`, `127.0.0.0/8`, `169.254.0.0/16`
     (covers AWS metadata `169.254.169.254`), `172.16.0.0/12`,
     `192.0.0.0/24`, `192.0.2.0/24` (TEST-NET), `192.168.0.0/16`,
     `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`,
     `100.64.0.0/10` (CGNAT), `224.0.0.0/4` (multicast),
     `240.0.0.0/4` (reserved), `255.255.255.255/32`.
   - **IPv6**: loopback/unspecified, link-local, unique-local, site-local,
     multicast, NAT64, 6to4, documentation, and IPv4-mapped ranges.
4. Hostnames `localhost` / `*.localhost` / `*.local` are rejected even if
   they resolve to a public IP.

`safeFetch` follows redirects manually, re-applying the guard at every hop.
Each connection is restricted to the validated public address set,
closing the DNS-rebinding gap between lookup and connect. Responses are capped
at 256 KB and each request times out after 6 seconds.

### Rate limiter (`lib/security/rate-limit.ts`)

In-memory per-IP token bucket: 12 requests / minute with bounded key storage.
The map resets on a function cold start, which is acceptable for a portfolio
deploy. For strict multi-instance limits, swap in Vercel KV / Upstash Redis —
`rateLimit()` is the only function to change. API routes also require JSON and
cap each request body before parsing it.

### Per-request CSP nonce (`proxy.ts`)

Issues a 128-bit base64 nonce per request, sets the CSP header on both
the request (so Next.js's runtime threads it onto its inline scripts) and
the response (so the browser enforces it). Production CSP:

```
script-src 'self' 'nonce-<random>' 'strict-dynamic'
```

Verified: 12 of 12 inline `<script>` tags in the rendered HTML carry the
nonce attribute matching the response header.

### Body / time caps

- Request timeout: 6 s per outbound `fetch` (`AbortSignal.timeout`).
- Response body: capped at 256 KB.
- TLS handshake: 7 s.

---

## Adding a new tool

1. Add an entry to `lib/tools/registry.ts`:

   ```ts
   {
     id: "my-tool",
     name: "My Tool",
     tagline: "What it does in one line.",
     description: "Long description for cards & metadata.",
     href: "/tools/my-tool",
     apiPath: "/api/tools/my-tool",
     status: "live",
     owaspRefs: ["A0X:2021 - Whatever"],
     tags: ["something"],
   }
   ```

2. Create `app/tools/my-tool/View.tsx` (`"use client"`) with the UI.

3. Create `app/tools/my-tool/page.tsx`:

   ```tsx
   import { toolMetadata } from "@/lib/tools/registry";
   import View from "./View";

   export const metadata = toolMetadata("my-tool");
   export default function Page() { return <View />; }
   ```

4. Create `app/api/tools/my-tool/route.ts` for the server logic. Always go
   through `safeFetch` for any user-supplied URL, and call `rateLimit(...)`
   at the top.

The home grid, sitemap, and OG image all pick up the new tool automatically.

---

## Scripts

```bash
npm run dev         # Next dev server with HMR
npm run build       # Production build
npm run start       # Production server (after build)
npm run typecheck   # tsc --noEmit
npm run lint        # ESLint
npm run test        # Vitest unit tests
```

CI (`.github/workflows/ci.yml`) audits production dependencies and runs
`typecheck` + `lint` + `test` + `build` on every push and pull request.

---

## Stack

- **Next.js 16** (App Router) on **Vercel**
- **TypeScript 5** strict mode
- **Tailwind 3** with a small dark palette (`ink-*` + `accent-*`)
- **Web Crypto API** for the JWT crack (no Node crypto in the browser)
- **`node:tls` + a tiny ASN.1 DER walker** for the cert viewer
- **Vitest** for fast unit coverage of pure security parsers and graders
- **No third-party JS deps** outside Next/React/Tailwind. Everything else
  shipped to the browser is hand-rolled and visible in `lib/`.

---

## Troubleshooting

**`SITE_URL` change isn't picked up.**
`robots.ts` and `sitemap.ts` are marked `force-dynamic` so they re-render
per request — no rebuild required. The OG image's metadata URL is set at
build time, so for that you do need a redeploy.

**CORS Tester says "no CORS headers".**
Many endpoints simply don't return CORS headers under any Origin (which
is the safe default). That's an info-level finding, not a vulnerability.

**Cert Viewer shows `authorized: true` for a known-bad cert site.**
Some test sites (e.g. `expired.badssl.com`) periodically rotate to valid
certificates. Compare against `openssl s_client -connect <host>:443 -servername <host>` —
if openssl says `Verify return code: 0 (ok)`, the cert is currently valid.

**Rate-limit responses on Vercel after a while.**
The in-memory bucket resets on a cold start, but a single hot function
will keep counting. Wait 60 seconds or swap in Vercel KV (single-file
change in `lib/security/rate-limit.ts`).

---

## License

[MIT](LICENSE).
