# AppSec Santa Security Tools

Free, open-source security scanning tools you can self-host on Cloudflare Workers. Scan HTTP headers, DNS, SSL/TLS, and subdomains from your own infrastructure with zero dependencies on third-party SaaS.

[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/appsecsanta/security-tools?style=social)](https://github.com/appsecsanta/security-tools)
[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/appsecsanta/security-tools)

---

## Tools

| Tool | Tests | What It Checks | Live Demo |
|------|-------|----------------|-----------|
| [Security Headers Checker](./headers-checker) | 11 | CSP, HSTS, X-Frame-Options, Cookies, CORS, SRI, Referrer-Policy, Permissions-Policy, CORP, X-Content-Type-Options, Redirection | [Try it](https://appsecsanta.com/tools/security-headers-checker) |
| [DNS Security Checker](./dns-checker) | 8 | DNSSEC, SPF, DMARC, CAA, NS Redundancy, MX, Zone Transfer, Dangling CNAME | [Try it](https://appsecsanta.com/tools/dns-security-checker) |
| [SSL/TLS Checker](./ssl-checker) | 8 | HTTPS, HSTS, Certificate Expiry, CT Logs, Chain of Trust, DANE/TLSA, HTTP Redirect, Mixed Content | [Try it](https://appsecsanta.com/tools/ssl-checker) |
| [Subdomain Finder](./subdomain-finder) | -- | Certificate Transparency log discovery via crt.sh | [Try it](https://appsecsanta.com/tools/subdomain-finder) |

Each tool runs as an independent Cloudflare Pages Function. Pick one or deploy all four.

---

## Quick Start

```bash
git clone https://github.com/appsecsanta/security-tools.git
cd security-tools/headers-checker
npm install
npx wrangler pages dev
# Open http://localhost:8788
```

Replace `headers-checker` with `dns-checker`, `ssl-checker`, or `subdomain-finder` to run a different tool.

---

## Deploy to Cloudflare

1. Fork this repository.
2. In the [Cloudflare Dashboard](https://dash.cloudflare.com/), go to **Workers & Pages > Create > Pages** and connect your fork.
3. Set the build output directory to the tool folder you want to deploy (e.g. `headers-checker`).
4. Add environment variables (see [Configuration](#configuration) below) and deploy.

Each tool can be deployed as a separate Pages project or combined under one project with multiple function routes.

---

## Architecture

```
<tool>/
├── functions/api/
│   └── *.js          # Serverless API endpoint (Cloudflare Pages Function)
├── demo/
│   └── index.html    # Standalone demo page (no framework needed)
├── package.json
└── README.md         # Tool-specific documentation
```

**How it works:**

- Each tool is a standalone Cloudflare Pages Function that receives a URL or domain, runs its checks server-side, and returns structured JSON results.
- **Token authentication** -- Requests are verified using HMAC-based tokens to prevent unauthorized use. The token endpoint issues short-lived tokens that must accompany each scan request.
- **Rate limiting** -- Uses Cloudflare KV to enforce per-IP rate limits and prevent abuse.
- **CORS** -- Configurable via the `ALLOWED_ORIGINS` environment variable. Defaults to rejecting cross-origin requests when not set.

### Configuration

| Variable | Purpose | Required |
|----------|---------|----------|
| `TURNSTILE_SECRET` | Cloudflare Turnstile secret key for bot protection | Yes |
| `ALLOWED_ORIGINS` | Comma-separated list of allowed CORS origins | Yes |
| `RATE_LIMIT_KV` | KV namespace binding for rate limiting | Recommended |

---

## API Reference

All endpoints accept `POST` requests with a JSON body containing a `url` or `domain` field plus a `token` for authentication.

### Security Headers Checker

```bash
curl -X POST https://your-deployment.pages.dev/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "token": "<turnstile-token>"}'
```

Runs 11 tests: Content-Security-Policy, Strict-Transport-Security (RFC 6797), X-Frame-Options, Secure Cookies, CORS configuration, Subresource Integrity, Referrer-Policy, Permissions-Policy, Cross-Origin-Resource-Policy, X-Content-Type-Options, and HTTPS redirection.

### DNS Security Checker

```bash
curl -X POST https://your-deployment.pages.dev/api/dns-check \
  -H "Content-Type: application/json" \
  -d '{"url": "example.com", "token": "<turnstile-token>"}'
```

Runs 8 tests: DNSSEC validation, SPF record analysis, DMARC policy check, CAA record presence, nameserver redundancy, MX record configuration, zone transfer protection, and dangling CNAME detection.

### SSL/TLS Checker

```bash
curl -X POST https://your-deployment.pages.dev/api/ssl-check \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "token": "<turnstile-token>"}'
```

Runs 8 tests: HTTPS availability, HSTS header (RFC 6797), certificate expiry, Certificate Transparency logs (RFC 6962), chain of trust validation, DANE/TLSA records (RFC 7671), HTTP-to-HTTPS redirect, and mixed content detection.

### Subdomain Finder

```bash
curl -X POST https://your-deployment.pages.dev/api/subdomain-finder \
  -H "Content-Type: application/json" \
  -d '{"url": "example.com", "token": "<turnstile-token>"}'
```

Discovers subdomains by querying Certificate Transparency logs through crt.sh, deduplicates results, and resolves each subdomain to check if it is live.

---

## Scoring Methodology

Each checker uses a weighted scoring system to produce a single grade from the individual test results.

- **Headers Checker** -- 13-grade scale from A+ down to F, modeled after the [Mozilla Observatory](https://observatory.mozilla.org/) v5 methodology. Each header contributes a weighted score; missing critical headers like CSP or HSTS carry heavy penalties.
- **DNS Checker** -- 8 weighted tests scored against best practices from [NIST SP 800-81](https://csrc.nist.gov/publications/detail/sp/800-81/2/final) (Secure DNS Deployment Guide). DNSSEC and DMARC carry the highest weight.
- **SSL/TLS Checker** -- 8 weighted tests aligned with the [OWASP TLS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html) and [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) (TLS 1.3). Certificate expiry and HSTS are weighted most heavily.

Full scoring breakdowns, weight tables, and grade boundaries are documented in each tool's `docs/scoring/` directory.

---

## Security

Found a vulnerability? Please report it responsibly. See [SECURITY.md](SECURITY.md) for our disclosure policy and contact details.

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on submitting issues, feature requests, and pull requests.

---

## License

This project is licensed under the [MIT License](LICENSE).

---

Built by [AppSec Santa](https://appsecsanta.com) -- curated application security tools comparison.
