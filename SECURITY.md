# Security Policy

## Defensive use only

Cyber Toolbox is built for authorized security testing, education, and portfolio demonstration. Do not use it to scan systems you do not own or do not have explicit permission to test.

The hosted tools intentionally avoid aggressive behavior. They perform bounded checks such as header inspection, TLS handshakes, CORS probes, and standards-based metadata audits. They are not vulnerability exploitation tools.

## Reporting vulnerabilities

If you find a vulnerability in Cyber Toolbox itself, please report it privately instead of opening a public issue with exploit details.

Preferred contact: `tinkthemaker@proton.me`

Please include:

- A clear description of the issue
- Steps to reproduce
- Affected route or component
- Potential impact
- Any suggested remediation

## Supported version

This is a portfolio project. The `main` branch is the supported version.

## Security design notes

The app includes several guardrails:

- Server-side URL scans pass through an SSRF guard and connect to the exact validated public IP.
- Redirects are followed manually and re-checked at each hop.
- Private, loopback, link-local, multicast, reserved, cloud metadata, `.local`, and `localhost` targets are blocked.
- API routes cap JSON request bodies and use a bounded per-IP in-memory rate limiter.
- The app sets static security headers through `vercel.json`.
- A per-request CSP nonce is generated in middleware for inline Next.js scripts.

These controls reduce abuse risk, but they do not make unauthorized scanning acceptable.
