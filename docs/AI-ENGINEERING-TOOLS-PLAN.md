# Plan: AI & Engineering Tools for Cyber Toolbox

Status: proposal · Target: incremental, one tool per PR

This plan extends the toolbox into two adjacent areas — **AI/LLM security**
(the OWASP Top 10 for LLM Applications) and **general engineering hygiene** —
without breaking any of the constraints that make the current codebase what it
is.

## Constraints every proposal below respects

Derived from the existing four tools, not invented for this document:

| Constraint | Why it matters here |
| --- | --- |
| **No third-party runtime deps** (Next/React/Tailwind only) | Every parser below is hand-rolled, the way `lib/tls/der.ts` is. Nothing needs an SDK. |
| **No secrets, no third-party APIs** | Nothing here calls a model provider. "AI tools" means *tools that audit AI surfaces*, not tools that consume an LLM. |
| **Every outbound URL goes through `guardUrl` / `safeFetch`** | Any new server route reuses `lib/security/ssrf.ts` unchanged. |
| **`rateLimit()` at the top of every route** | Same three-line preamble as `app/api/tools/cors-tester/route.ts`. |
| **Report shape is `Finding[]` / `FindingGroup[]`** | New tools render through the existing `FindingsList` + `SeverityBadge`, so UI cost stays near zero. |
| **Pure logic lives in `lib/`, is unit-tested with vitest** | CI already runs `npm run test`; each tool below lands with tests for its analyzer. |
| **Registry-driven** | Adding to `lib/tools/registry.ts` wires up the home grid, sitemap, and OG image for free. |

A useful side effect: the **client-only** tools (marked below) need no API
route, no SSRF surface, no `vercel.json` entry, and no rate limiting — they are
the cheapest and safest things to ship, exactly like JWT Inspector.

---

## Track A — AI / LLM security tools

### A1. AI Crawler & Content Policy Auditor — *server route*

**What:** Point it at a domain; it fetches and grades the site's AI-facing
policy surface:

- `/robots.txt` — directives for `GPTBot`, `ClaudeBot`, `Google-Extended`,
  `CCBot`, `PerplexityBot`, `Bytespider`, `Applebot-Extended`, and friends;
  flags "blocks nothing", "blocks everything", and self-contradicting groups.
- `/llms.txt` and `/llms-full.txt` — presence, size, whether it points at
  routes that 404.
- `/.well-known/ai.txt`, `/ai.txt` — TDM/AI usage declarations.
- Response headers — `X-Robots-Tag: noai, noimageai`, `TDM-Reservation`.
- Cross-checks: `llms.txt` advertising paths that `robots.txt` disallows.

**Why it earns a slot:** it is a real, current gap that nobody has a clean
checker for, and it is *pure fetch + parse* — the exact shape of Misconfig
Mapper. Highest value-to-risk ratio in this plan.

**Files:** `lib/aipolicy/{fetch,robots,llmstxt,analyze,types}.ts`,
`app/api/tools/ai-policy/route.ts`, `app/tools/ai-policy/{page,View}.tsx`,
`tests/aipolicy/analyze.test.ts`. Add `maxDuration: 15` to `vercel.json`.

**Effort:** M. Network: 4–6 guarded GETs. OWASP: A05 + LLM-adjacent.

---

### A2. Prompt Injection Linter — *client-only*

**What:** Paste a system prompt / RAG or agent template; get graded findings on
structural weaknesses:

- Untrusted content interpolated with **no delimiter** (`{{context}}`,
  `${userInput}` sitting inline in instruction text).
- Missing "content below is data, not instructions" framing.
- Instruction-override bait already present in the text ("ignore previous…").
- **Secrets in the prompt** — API keys, internal hostnames, connection strings.
- Tool/authority language without a confirmation gate ("you may run any
  command", "always approve").
- No output-format constraint, so injected output flows straight downstream.
- Conflicting or duplicated instructions; unreachable trailing rules.

**Why:** maps to **OWASP LLM01 (Prompt Injection)** and **LLM06 (Sensitive
Information Disclosure)**, runs entirely in the tab (prompts are sensitive —
the "your text never leaves your browser" story is the same one JWT Inspector
already tells and it lands well), and it is 100% pure functions, so it is
trivially testable.

**Files:** `lib/promptlint/{rules,analyze,types}.ts`,
`app/tools/prompt-linter/{page,View}.tsx`, `tests/promptlint/rules.test.ts`.
No route, no `vercel.json` change.

**Effort:** M (the rule set is the work, not the plumbing). Network: none.

---

### A3. AI Key & Credential Leak Linter — *client-only*

**What:** Paste a config file, `.env`, or code snippet; it flags provider
credentials by prefix pattern **plus** Shannon-entropy scoring, and shows
masked matches only (`sk-ant-…4f2a`):

`sk-ant-*` (Anthropic), `sk-*`/`sk-proj-*` (OpenAI), `AIza*` (Google),
`hf_*` (Hugging Face), `r8_*` (Replicate), `gsk_*` (Groq), `xai-*`,
`pplx-*`, plus generic `AWS_SECRET_ACCESS_KEY`, bearer tokens, and private-key
PEM blocks.

Each finding gets a remediation line: rotate first, then purge history.

**Why:** ships in an afternoon, is genuinely useful, and pairs naturally with
A4 below. Same client-only safety posture — the pasted secret never leaves the
tab, which is the whole point.

**Files:** `lib/secretlint/{patterns,entropy,analyze}.ts`,
`app/tools/secret-linter/{page,View}.tsx`, `tests/secretlint/*.test.ts`.

**Effort:** S. Network: none. OWASP: A02 / LLM06.

---

### A4. MCP & Agent Config Auditor — *client-only*

**What:** Paste an MCP server config (`mcp.json`, `claude_desktop_config.json`,
`.mcp.json`) and grade each server entry:

- `npx -y <unpinned>` / `uvx` from a registry with no version pin — silent
  remote-code update on every launch.
- Inline secrets in `env` (hand off to the A3 pattern set — shared module).
- Filesystem servers rooted at `/`, `~`, or the home directory.
- `command: bash -c …` / shell-wrapped launches.
- Remote servers over plain `http://`, or pointed at an IP literal.
- Tool-permission blocks that pre-approve broad wildcards.

**Why:** this is where "AI" and "security misconfiguration" actually meet in
2026, and there is no tidy checker for it. Strong differentiator for a
portfolio piece; reuses A3's pattern module so the marginal cost is low.

**Files:** `lib/mcplint/{rules,analyze,types}.ts`,
`app/tools/mcp-auditor/{page,View}.tsx`, `tests/mcplint/rules.test.ts`.

**Effort:** M. Network: none. Depends on: A3 (shared secret patterns).

---

### A5. Exposed AI Endpoint Probe — *server route, ship last*

**What:** Same probe pattern as `lib/misconfig/probes.ts`, aimed at unauthenticated
AI infrastructure left open on a host: `/v1/models`, `/v1/chat/completions`
(GET → expect 401/405, flag a 200), Ollama `/api/tags`, LangServe `/invoke`,
Gradio `/config`, `/openapi.json`, vector-DB consoles.

**Why it is last:** it is the only proposal that is meaningfully *active*
probing. It stays inside what the toolbox already does (`.git/HEAD` and
`/server-status` probes are the same class), but it deserves the strictest
treatment: GET/HEAD only, no request bodies, never send a prompt, an explicit
"only scan what you own" interstitial, and short timeouts.

**Files:** `lib/aiendpoints/{probes,analyze,types}.ts`,
`app/api/tools/ai-endpoints/route.ts`, `app/tools/ai-endpoints/{page,View}.tsx`,
`tests/aiendpoints/analyze.test.ts`. `vercel.json`: `maxDuration: 20`.

**Effort:** M. Network: ~8 guarded probes. OWASP: A05 / LLM.

---

## Track B — Engineering hygiene tools

### B1. DNS & Email Hygiene Check — *server route, `node:dns` only*

Resolves and grades: SPF (present, single record, no `+all`, lookup count ≤ 10),
DMARC (`p=none` vs `quarantine`/`reject`, `rua` present), DKIM selector probing
for common selectors, MX sanity, CAA presence, DNSSEC (`DS` record), and
dangling-CNAME subdomain-takeover signals.

Uses `node:dns/promises` — **no HTTP at all**, so the SSRF surface is nil.
Pairs naturally with the existing TLS viewer. **Effort:** M. **Highest value in
Track B.**

### B2. Open Redirect Tester — *server route*

Already named in the README's "planned" list. Enumerates common redirect params
(`next`, `url`, `redirect`, `return_to`, `dest`, `continue`), sends a benign
off-site value through `safeFetch` with redirects **not** followed, and grades
the `Location` header: same-origin (pass), off-site (fail), protocol-relative
`//evil` and `\/\/evil` bypasses, and open `javascript:` targets.
**Effort:** M. OWASP: A01/A10.

### B3. Cache & Compression Auditor — *server route*

Grades `Cache-Control` on HTML vs static assets, `Vary` correctness (the
`Vary: Origin` bug the CORS tester already hints at), `ETag`/`Last-Modified`,
`Age`/CDN headers, compression negotiation, and the classic *private data
cached publicly* pattern. Cheap: one or two requests, reuses everything.
**Effort:** S.

### B4. Robots & Sitemap Auditor — *server route*

Also on the README list; largely **free if A1 ships first** — the robots.txt
parser and fetch layer are the same module. Adds sitemap XML validation, URL
count/size caps, `robots.txt` ↔ sitemap disagreement, and 404/redirect
sampling. **Effort:** S when built after A1.

---

## Track C — Engineering enablement (repo-internal)

Small, unglamorous, pays for itself by tool #6:

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
5. **Shared probe harness** — A1, A5, B2, B3, B4 all do "fire N guarded
   requests, collect status + headers, classify". Factor that out of
   `lib/misconfig/probes.ts` into `lib/security/probe-runner.ts` **before**
   the third consumer, not after the fifth.

---

## Sequencing

Each phase is independently shippable, and each is one PR per tool.

| Phase | Ships | Rationale |
| --- | --- | --- |
| **0** | C1 (`CLAUDE.md`), C2 (scaffolder), C4 (registry test) | ~half a day; every later tool gets cheaper. |
| **1** | **A2 Prompt Injection Linter**, **A3 Key Leak Linter** | Client-only: no network, no route, no new attack surface. Fastest path to "the toolbox does AI now". |
| **2** | **A1 AI Crawler & Policy Auditor** + C5 (probe harness) | First AI server tool; extract the shared harness while there are exactly two consumers. |
| **3** | **A4 MCP Config Auditor**, **B1 DNS & Email Hygiene** | The two strongest differentiators. A4 reuses A3; B1 reuses nothing but adds a new primitive (`node:dns`). |
| **4** | **B4 Robots/Sitemap**, **B3 Cache/Compression**, **B2 Open Redirect** | Cheap fills once the harness exists. |
| **5** | **A5 Exposed AI Endpoint Probe** | Ships last, deliberately: most active probing, needs the strictest guardrails and the clearest consent copy. |

## Definition of done, per tool

1. Registry entry in `lib/tools/registry.ts` (`status: "soon"` first if you want
   it visible on the grid before it lands — `ToolCard` already renders "Soon"
   as non-clickable and `sitemap.ts` filters to `live`, so this is safe).
2. Analyzer in `lib/<area>/`, pure and dependency-free.
3. Vitest suite covering pass/warn/fail for each rule.
4. Route with the `rateLimit` + `safeFetch` preamble (server tools only).
5. `vercel.json` `maxDuration` entry (server tools only).
6. README table row + `docs/` note if the tool has a non-obvious threat model.
7. `npm run typecheck && npm run test && npm run lint && npm run build` green.

## Open questions

- **Naming:** does the site want an explicit "AI" category on the home grid, or
  do these just mix into the existing list? The registry has `tags` already —
  an `ai` tag plus a filter row on `app/page.tsx` is a small change.
- **OWASP refs:** the registry's `owaspRefs` currently carries Top 10 (Web)
  strings. AI tools want *OWASP Top 10 for LLM Applications* refs
  (`LLM01:2025 - Prompt Injection`). Recommend keeping one field and letting
  the string carry the taxonomy, rather than adding a second field.
- **A5 consent:** the existing tools warn in prose. An active AI-endpoint probe
  may warrant a checkbox before the first scan. Product call, not a technical one.
