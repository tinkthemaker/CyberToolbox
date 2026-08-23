# Plan: AI & Engineering Tools for Cyber Toolbox

Status: proposal · Target: incremental, one tool per PR

This plan extends the toolbox into two adjacent areas — **AI/LLM security**
(the OWASP Top 10 for LLM Applications) and **general engineering hygiene** —
without breaking any of the constraints that make the current codebase what it
is.

## The bar a new tool has to clear

Beyond the architectural constraints below, the four live tools share a
property worth stating explicitly, because it is the thing that makes them
credible: **each one returns a verifiable fact.** The header is present or it
is not. The certificate expires on a date. `alg` is `none` or it is not. The
README's troubleshooting section actively invites the user to check the cert
verdict against `openssl s_client` — the verdict survives that check.

A tool that returns a *heuristic opinion* dressed as a verdict does not belong
here, however useful the underlying idea. That test drove the cuts recorded at
the end of this document.

## Constraints every proposal below respects

Derived from the existing four tools, not invented for this document:

| Constraint | Why it matters here |
| --- | --- |
| **No third-party runtime deps** (Next/React/Tailwind only) | Every parser below is hand-rolled, the way `lib/tls/der.ts` is. Nothing needs an SDK. |
| **No secrets, no third-party APIs** | Nothing here calls a model provider. "AI tools" means *tools that audit AI surfaces*, not tools that consume an LLM. |
| **Every outbound URL goes through `guardUrl` / `safeFetch`** | Any new server route reuses `lib/security/ssrf.ts` unchanged. |
| **`rateLimit()` at the top of every route** | Same three-line preamble as `app/api/tools/cors-tester/route.ts`. Note its scope before adding five more routes: the bucket is per-process in-memory, keyed by `clientKeyFromHeaders`, so it limits each serverless instance separately and resets on cold start. Fine for a portfolio deploy; if these tools see real traffic, swap `lib/security/rate-limit.ts` for a shared store (Vercel KV/Upstash) — one function, one call site. |
| **Report shape is `Finding[]` / `FindingGroup[]`** | New tools render through the existing `FindingsList` + `SeverityBadge`, so UI cost stays near zero. |
| **Pure logic lives in `lib/`, is unit-tested with vitest** | CI already runs `npm run test`; each tool below lands with tests for its analyzer. |
| **Registry-driven** | Adding to `lib/tools/registry.ts` wires up the home grid, sitemap, and OG image for free. |

A useful side effect: the **client-only** tools (marked below) need no API
route, no SSRF surface, no `vercel.json` entry, and no rate limiting — they are
the cheapest and safest things to ship, exactly like JWT Inspector.

---

## Track A — AI / LLM security tools

### A4. MCP & Agent Config Auditor — *client-only* · **lead tool**

**What:** Paste an MCP server config (`mcp.json`, `claude_desktop_config.json`,
`.mcp.json`) and grade each server entry:

- `npx -y <unpinned>` / `uvx` from a registry with no version pin — silent
  remote-code update on every launch.
- Inline secrets in `env` (hand off to the A3 pattern set — shared module).
- Filesystem servers rooted at `/`, `~`, or the home directory.
- `command: bash -c …` / shell-wrapped launches.
- Remote servers over plain `http://`, or pointed at an IP literal.
- Tool-permission blocks that pre-approve broad wildcards.

**Why it leads:** every rule is a fact, not a heuristic — a package without a
version pin *is* unpinned; a server on `http://` *is* plaintext; a root at `~`
*is* the whole home directory. Real threat model (supply-chain RCE), genuinely
under-served by existing tooling, and it takes the same client-only posture as
JWT Inspector: the config never leaves the tab.

**Files:** `lib/mcplint/{rules,analyze,types}.ts`,
`app/tools/mcp-auditor/{page,View}.tsx`, `tests/mcplint/rules.test.ts`.

**Effort:** M. Network: none. Depends on: A3 (shared secret patterns).

---

### A3. AI Key & Credential Leak Linter — *client-only*

**What:** Paste a config file, `.env`, or code snippet; it flags provider
credentials by prefix pattern, and shows masked matches only (`sk-ant-…4f2a`):

`sk-ant-*` (Anthropic), `sk-*`/`sk-proj-*` (OpenAI), `AIza*` (Google),
`hf_*` (Hugging Face), `r8_*` (Replicate), `gsk_*` (Groq), `xai-*`,
`pplx-*`, plus generic `AWS_SECRET_ACCESS_KEY`, bearer tokens, and private-key
PEM blocks.

**Deterministic rules decide the verdict; entropy never does.** A `pass`/`fail`
requires a prefix or format rule to match, and every finding names the rule that
fired so the user can check it. Shannon entropy runs only as a secondary signal
on values no rule matched, and those surface at `info` as *observations* —
"high-entropy string, no known provider format" — never as a credential verdict.
Keeping entropy out of the verdict is what holds this tool to the bar above;
an earlier draft billed entropy as a co-equal detector, which contradicted it.

Each finding gets a remediation line: rotate first, then purge history.

**Why:** a prefix either matches or it does not, so the verdict is checkable.
Novelty is admittedly low — gitleaks and trufflehog cover this ground better —
but it is an afternoon of work and **A4 needs the pattern module anyway**, so
build it first and let A4 import it.

**Files:** `lib/secretlint/{patterns,entropy,analyze}.ts`,
`app/tools/secret-linter/{page,View}.tsx`, `tests/secretlint/*.test.ts`.

**Effort:** S. Network: none. OWASP: A02 / LLM06.

---

### A1. AI Crawler & Content Policy Auditor — *server route* · **scope decision required**

**What:** Point it at a domain; it fetches and grades the site's AI-facing
policy surface:

- `/robots.txt` — directives for `GPTBot`, `ClaudeBot`, `Google-Extended`,
  `CCBot`, `PerplexityBot`, `Bytespider`, `Applebot-Extended`, and friends;
  flags "blocks nothing", "blocks everything", and self-contradicting groups.
- `/llms.txt` and `/llms-full.txt` — presence, size, whether it points at
  routes that 404. **Only same-origin URLs are dereferenced, capped at 20 per
  scan**: the advertised list is attacker-controlled content, so following
  off-origin entries would turn the scanner into a request amplifier for
  third-party hosts that never opted in. `guardUrl` blocks private and reserved
  addresses but deliberately permits public ones, so the origin check is a
  separate gate, applied before any `safeFetch`. Off-origin entries are still
  *listed* in the report, just not fetched.
- `/.well-known/ai.txt`, `/ai.txt` — TDM/AI usage declarations.
- Response headers — `X-Robots-Tag: noai, noimageai`, `TDM-Reservation`.
- Cross-checks: `llms.txt` advertising paths that `robots.txt` disallows.

**Technically the cleanest proposal here** — pure fetch + parse, the exact
shape of Misconfig Mapper, reusing its fetch layer almost verbatim, and every
output is a fact.

**But it is not a security tool.** It audits content licensing and crawler
policy. There is no honest OWASP mapping for it; an earlier draft of this
document claimed "A05 + LLM-adjacent" and that was a fudge. Shipping it means
the site's remit widens from "web-security tools" to something closer to "web
surface auditing" — including the tagline, the About page, and the OG copy.

**That is a product decision, not a technical one** — see *Decisions needed*
below. Build it if the answer is yes; drop it cleanly if the answer is no.

**Files:** `lib/aipolicy/{fetch,robots,llmstxt,analyze,types}.ts`,
`app/api/tools/ai-policy/route.ts`, `app/tools/ai-policy/{page,View}.tsx`,
`tests/aipolicy/analyze.test.ts`. Add `maxDuration: 15` to `vercel.json`.

**Effort:** M. Network: 4–6 guarded GETs.

---

## Track B — Engineering hygiene tools

All four are in scope and sequenced below. They are conventional web-quality
tools rather than novel ones, which is the point: they are well-understood,
their verdicts are checkable, and each reuses machinery the toolbox already has.

### B1. DNS & Email Hygiene Check — *server route, `node:dns` only*

Resolves and grades: SPF (present, single record, no `+all`, lookup count ≤ 10),
DMARC (`p=none` vs `quarantine`/`reject`, `rua` present), DKIM selector probing
for common selectors, MX sanity, CAA presence, DNSSEC (`DS` record), and
dangling-CNAME subdomain-takeover signals.

Uses `node:dns/promises` — **no HTTP at all**, so the SSRF surface is nil.
Pairs naturally with the existing TLS viewer. **Effort:** M. **Strongest tool
in Track B.**

### B2. Open Redirect Tester — *server route*

Already named in the README's "planned" list. Enumerates common redirect params
(`next`, `url`, `redirect`, `return_to`, `dest`, `continue`), sends a benign
off-site value, and grades the **first** `Location` header: same-origin (pass),
off-site (fail), protocol-relative `//evil` and `\/\/evil` bypasses, and open
`javascript:` targets.

**This needs a fetch primitive the repo does not have yet.** `safeFetch` follows
3xx responses itself (`lib/security/safe-fetch.ts:120-122`, up to
`MAX_REDIRECTS`) and returns only the terminal response's headers, and
`SafeFetchInit` (`method`, `headers`, `deadlineMs`) has no opt-out. B2 therefore
also ships a guarded single-hop mode — an added `SafeFetchInit` flag, or a small
sibling primitive — that stops at the first response and exposes its raw
`Location` without dereferencing it. Multi-hop stays the default for every
existing caller. Count that in the estimate: **Effort:** M, and it is the reason
B2 rather than B3 is the phase that touches the fetch layer. OWASP: A01/A10.

### B3. Cache & Compression Auditor — *server route*

Grades `Cache-Control` on HTML vs static assets, `Vary` correctness (the
`Vary: Origin` bug the CORS tester already hints at), `ETag`/`Last-Modified`,
`Age`/CDN headers, and compression negotiation.

**The *private data cached publicly* pattern caps at `warn`, not `fail`.**
Proving cross-user response reuse needs two identities — an authenticated and an
anonymous request, or two distinct sessions — and the toolbox takes no
credentials for a target, so it cannot run that test. What it can state as fact
is the precondition: a `Cache-Control: public` (or missing) response that also
carries `Set-Cookie` or `Authorization`-varying content. Report that as a warning
naming the missing evidence, and never as a confirmed confidentiality bug. This
is the same bar that cut the prompt-injection linter: state the checkable fact,
not the inference. Cheap: one or two requests, reuses everything. **Effort:** S.

### B4. Robots & Sitemap Auditor — *server route*

Also on the README list. Validates sitemap XML, URL count/size caps,
`robots.txt` ↔ sitemap disagreement, and 404/redirect sampling of advertised
URLs.

Sampling of advertised URLs follows the same same-origin + 20-URL cap as A1,
and for the same reason: sitemap contents are attacker-controlled.

**Dependency note:** B4 and A1 share a `robots.txt` parser, and **B4 ships
first** (Phase 4 vs Phase 5), so B4 introduces it — `lib/robots/parse.ts`,
costed at **M** — and A1 imports it later rather than the other way round. An
earlier draft had this backwards, claiming B4 was nearly free off a parser A1
would not have written yet. The upside is unchanged, just relocated: if the A1
scope decision comes back "no", the parser still lands with B4 and nothing is
stranded.

---

## Track C — Engineering enablement (repo-internal)

Small, unglamorous, pays for itself by tool #4:

1. **`CLAUDE.md`** at the repo root — the "adding a new tool" contract from the
   README, plus the non-negotiables (`safeFetch`, `rateLimit`, no new deps,
   tests for every `lib/` analyzer) in a form an agent reads first.
2. **Tool scaffolder** — `npm run new:tool -- <id>` emits the registry stub,
   `page.tsx`/`View.tsx`, the route with the rate-limit preamble already in
   place, and a test file. Removes the four-file boilerplate and, more
   importantly, makes it impossible to forget the security preamble.
3. **Coverage gate** — vitest `--coverage` in CI (already runs `npm run test`),
   with a floor on `lib/**` so analyzers cannot land untested.
4. **Registry contract test** — one test asserting every `live` tool has a
   reachable `href`, a unique `id`, and, when `apiPath` is set, a matching
   `vercel.json` entry. Catches the most likely copy-paste mistake.
5. **Shared probe harness** — A1, B2, B3, and B4 all do "fire N guarded
   requests, collect status + headers, classify". Factor that out of
   `lib/misconfig/probes.ts` into `lib/security/probe-runner.ts` **before**
   the third consumer, not after the fourth.

---

## Sequencing

Each phase is independently shippable, one PR per tool.

| Phase | Ships | Rationale |
| --- | --- | --- |
| **0** | C1 (`CLAUDE.md`), C2 (scaffolder), C4 (registry test) | ~half a day; every later tool gets cheaper. |
| **1** | **A3 Key Leak Linter** → **A4 MCP Config Auditor** | Client-only: no network, no route, no new attack surface. A3 first because A4 imports its pattern module. A4 is the differentiator — lead the announcement with it. |
| **2** | **B1 DNS & Email Hygiene** | Adds a new primitive (`node:dns`) with zero HTTP surface. |
| **3** | **B2 Open Redirect** + C5 (probe harness) | First new consumer of the fetch layer; extract the shared harness here, while there are two consumers rather than four. |
| **4** | **B3 Cache & Compression**, **B4 Robots & Sitemap** | Cheap fills once the harness exists. |
| **5** | **A1 AI Crawler & Policy Auditor** | Gated on the scope decision below. Imports the `robots.txt` parser B4 landed in Phase 4, so if the answer is yes it is cheaper than its section implies. |

## Definition of done, per tool

1. Registry entry in `lib/tools/registry.ts` (`status: "soon"` first if you want
   it visible on the grid before it lands — `ToolCard` already renders "Soon"
   as non-clickable and `sitemap.ts` filters to `live`, so this is safe).
2. Analyzer in `lib/<area>/`, pure and dependency-free.
3. Vitest suite covering pass/warn/fail for each rule.
4. Route with the `rateLimit` preamble (every server tool) and `safeFetch` for
   every user-supplied URL (HTTP-fetching tools only — B1 is `node:dns`-only and
   makes no HTTP request, so it takes the rate limiter and nothing else).
5. `vercel.json` `maxDuration` entry (server tools only).
6. README table row + `docs/` note if the tool has a non-obvious threat model.
7. `npm run typecheck && npm run test && npm run lint && npm run build` green.

---

## Considered and cut

Recorded with reasoning so the calls are reviewable, and reversible in one
commit if the reasoning does not hold up.

### Prompt Injection Linter — cut

Paste a system prompt or RAG template, get findings on undelimited
interpolation, missing "data, not instructions" framing, instruction-override
bait, and ungated tool authority.

**Why cut:** it fails the verifiable-fact bar. "Missing data-vs-instruction
framing" is a regex heuristic the user cannot check, and it will false-positive
heavily on ordinary prompts. The deeper problem is the green verdict: there is
no known structural fix for prompt injection, so a passing grade would imply an
assurance the tool cannot back — worse than shipping nothing in a security
toolbox. Its one genuinely checkable rule, *secrets embedded in the prompt*, is
already **A3**.

### Exposed AI Endpoint Probe — cut

Probe a host for unauthenticated AI infrastructure: `/v1/models`,
`/v1/chat/completions`, Ollama `/api/tags`, LangServe `/invoke`, Gradio
`/config`.

**Why cut:** the toolbox's own safety guard removes the valuable case. The
classic finding is an unauthenticated Ollama on an internal address, and
`lib/security/ssrf.ts` blocks `10.0.0.0/8`, `172.16.0.0/12`, and
`192.168.0.0/16` by design, re-checking on every redirect hop. (Ports are
unrestricted, so `:11434` on a *public* IP is reachable — but that is the rare
case, not the valuable one.) What remains is probing third parties' public
inference endpoints: the most aggressive action in the box for the least yield.

---

## Decisions needed

1. **Does the site's remit stay "web-security tools"?** This gates **A1**
   (Phase 5) and changes B4's cost. Shipping A1 means widening the tagline,
   About page, and OG copy toward "web surface auditing". Recommendation: decide
   before Phase 4, since B4 shares A1's parser.
2. **Do AI tools get their own home-grid category?** The registry already has
   `tags` — an `ai` tag plus a filter row on `app/page.tsx` is a small change.
3. **`owaspRefs` taxonomy.** AI tools want *OWASP Top 10 for LLM Applications*
   refs (`LLM01:2025 - Prompt Injection`) alongside the existing web Top 10
   strings. Recommendation: keep one field and let the string carry the
   taxonomy, rather than adding a second field.
