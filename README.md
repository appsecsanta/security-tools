<p align="center">
  <img src="https://appsecsanta.com/images/appsecsanta-logo.png" width="200" alt="AppSec Santa" />
</p>

<h1 align="center">AppSec Santa Security Tools</h1>

<p align="center">
  Free, open-source security scanning tools. Self-host on Cloudflare Workers.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="MIT License" /></a>
  <a href="https://github.com/appsecsanta/security-tools/stargazers"><img src="https://img.shields.io/github/stars/appsecsanta/security-tools?style=for-the-badge&logo=github" alt="GitHub Stars" /></a>
  <a href="https://developers.cloudflare.com/pages/functions/"><img src="https://img.shields.io/badge/Runs_on-Cloudflare_Workers-F38020?style=for-the-badge&logo=cloudflare&logoColor=white" alt="Cloudflare Workers" /></a>
</p>

<p align="center">
  <a href="https://appsecsanta.com">Website</a> ·
  <a href="#tools">Live Demos</a> ·
  <a href="docs/">Docs</a> ·
  <a href="CONTRIBUTING.md">Contributing</a> ·
  <a href="LICENSE">License</a>
</p>

---

## Tools

<br />

### Security Headers Checker

> **11 security tests** · A+ to F grading · Mozilla Observatory v5 scoring

```
CSP · HSTS · X-Frame-Options · Cookies · CORS · SRI
Referrer-Policy · Permissions-Policy · CORP · X-Content-Type-Options · Redirection
```

[Documentation](./headers-checker) · [Live Demo](https://appsecsanta.com/tools/security-headers-checker)

<br />

### DNS Security Checker

> **8 security tests** · NIST SP 800-81 aligned · Email auth coverage

```
DNSSEC · SPF · DMARC · CAA · NS Redundancy · MX · Zone Transfer · Dangling CNAME
```

[Documentation](./dns-checker) · [Live Demo](https://appsecsanta.com/tools/dns-security-checker)

<br />

### SSL/TLS Checker

> **8 security tests** · RFC 8446 aligned · Certificate transparency

```
HTTPS · HSTS · Cert Expiry · CT Logs · Chain of Trust · DANE/TLSA · HTTP Redirect · Mixed Content
```

[Documentation](./ssl-checker) · [Live Demo](https://appsecsanta.com/tools/ssl-checker)

<br />

### Subdomain Finder

> **Certificate Transparency discovery** · crt.sh integration · Live resolution

```
CT Log Search · Deduplication · DNS Resolution · Wildcard Handling
```

[Documentation](./subdomain-finder) · [Live Demo](https://appsecsanta.com/tools/subdomain-finder)

<br />

---

## How It Works

Each tool runs as an independent [Cloudflare Pages Function](https://developers.cloudflare.com/pages/functions/) — a serverless endpoint that accepts a URL or domain, runs its checks server-side, and returns structured JSON.

```
                                    Cloudflare Pages Function
                                   ┌──────────────────────────┐
                                   │                          │
  Browser ──── Demo Page ────────► │  Token Verification      │
                                   │         │                │
                                   │         ▼                │
                                   │  Rate Limit Check (KV)   │
                                   │         │                │
                                   │         ▼                │
                                   │  Run Security Tests ─────┼──── Target Site
                                   │         │                │
                                   │         ▼                │
                                   │  Return JSON Results     │
                                   │                          │
                                   └──────────────────────────┘
```

**Token authentication** prevents unauthorized use via HMAC-based short-lived tokens. **Rate limiting** uses Cloudflare KV to enforce per-IP limits. **CORS** is configurable through the `ALLOWED_ORIGINS` environment variable.

---

## Quick Start

```bash
git clone https://github.com/appsecsanta/security-tools.git
cd security-tools/headers-checker
npm install
npx wrangler pages dev
```

Open `http://localhost:8788`. Replace `headers-checker` with any tool directory to run a different checker.

---

## Deploy

Three steps to self-host on Cloudflare Pages:

1. Fork this repository
2. Connect your fork in the Cloudflare Dashboard under **Workers & Pages**
3. Set environment variables and deploy

Each tool deploys as its own Pages project — pick one or run all four. Full walkthrough in [docs/self-hosting.md](docs/self-hosting.md).

---

## Scoring

Each tool produces a weighted grade from its individual test results:

- **Headers** — 13-grade scale (A+ to F) modeled on Mozilla Observatory v5. Details in [docs/scoring/headers.md](docs/scoring/headers.md).
- **DNS** — 8 weighted tests scored against NIST SP 800-81 best practices. Details in [docs/scoring/dns.md](docs/scoring/dns.md).
- **SSL/TLS** — 8 weighted tests aligned with the OWASP TLS Cheat Sheet and RFC 8446. Details in [docs/scoring/ssl.md](docs/scoring/ssl.md).

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

Found a vulnerability? See [SECURITY.md](SECURITY.md) for our disclosure policy.

## License

This project is licensed under the [MIT License](LICENSE).

---

<p align="center">
  Built by <a href="https://appsecsanta.com">AppSec Santa</a> — curated application security tools comparison.
</p>
