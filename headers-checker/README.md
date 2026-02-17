# Security Headers Checker

Analyzes HTTP response headers against 11 security tests based on the Mozilla Observatory v5 algorithm, producing an A+ to F grade on a 13-point scale.

[Live Demo](https://appsecsanta.com/tools/security-headers-checker) | [Scoring Methodology](../docs/scoring/headers.md) | [Back to Catalog](../)

---

## What It Tests

| Test | Score Impact | What It Checks |
|------|-------------|----------------|
| Content-Security-Policy | -25 (missing) to +10 (strict) | Validates CSP header or meta tag. Penalizes `unsafe-inline`, `unsafe-eval`, wildcard sources, and insecure schemes. Awards bonus for `default-src 'none'` or nonce/hash usage. |
| Cookies | -40 (no Secure) to +5 (all flags) | Checks session cookies for `Secure`, `HttpOnly`, and `SameSite` attributes. Detects missing flags on CSRF cookies and invalid SameSite values. |
| CORS | -50 (origin reflection + credentials) to 0 | Sends a request with a spoofed `Origin: https://evil.example.com` header. Flags reflected origins with credentials, reflected origins without credentials, and wildcard origins. |
| Redirection | -20 (missing) to 0 (correct) | Verifies HTTP requests redirect to HTTPS. Checks for 301 status, same-host redirect, and no intermediate HTTP hops. |
| Referrer-Policy | -5 (unsafe-url) to +5 (strict) | Checks header or meta tag value. Awards points for `no-referrer`, `same-origin`, `strict-origin`, or `strict-origin-when-cross-origin`. |
| Strict-Transport-Security | -20 (missing) to +5 (preloaded) | Validates HSTS header presence, `max-age` >= 6 months, `includeSubDomains`, and `preload` directives. |
| Subresource Integrity | -50 (insecure external scripts) to +5 (all covered) | Parses HTML body for external `<script>` tags and checks for `integrity` attributes. Distinguishes between HTTPS-loaded and insecure scripts. |
| X-Content-Type-Options | -5 (missing) to 0 (nosniff) | Checks for the `nosniff` value to prevent MIME-type sniffing. |
| X-Frame-Options | -20 (missing) to +5 (CSP frame-ancestors) | Checks for `DENY` or `SAMEORIGIN`. Also passes if CSP includes `frame-ancestors 'none'` or `frame-ancestors 'self'`. |
| Cross-Origin-Resource-Policy | -5 (invalid) to 0 (set) | Checks for `same-origin`, `same-site`, or `cross-origin` values. |
| Permissions-Policy | 0 (informational) | Detects whether the header is set. Currently scored as informational only. |

**Informational checks (not scored):** Cross-Origin-Opener-Policy (COOP), Cross-Origin-Embedder-Policy (COEP), and server information leakage (Server version, X-Powered-By, X-AspNet-Version).

## Quick Start

```bash
git clone https://github.com/appsecsanta/security-tools.git
cd security-tools/headers-checker
npm install
npx wrangler pages dev
# Open http://localhost:8788
```

## API Reference

### GET /api/token

Returns a signed HMAC token for authenticating scan requests. Tokens are bound to the requester's IP address and expire after 5 minutes.

**Response:**

```json
{
  "token": "1708200000000.a1b2c3d4e5f6..."
}
```

**Rate limit:** 30 requests per IP per hour.

### POST /api/scan

Scans a URL and returns security header analysis with scores for all 11 tests.

**Request body:**

```json
{
  "url": "https://example.com",
  "token": "<token-from-GET-/api/token>"
}
```

The `url` field accepts URLs with or without a protocol prefix. If omitted, `https://` is prepended automatically.

**Response:**

```json
{
  "url": "https://example.com",
  "finalUrl": "https://example.com/",
  "grade": "B+",
  "score": 80,
  "uncurvedScore": 80,
  "scannedAt": "2026-02-17T12:00:00.000Z",
  "algorithmVersion": 5,
  "tests": {
    "csp": { "result": "csp-implemented-with-no-unsafe", "scoreModifier": 5, "pass": true, "description": "...", "recommendation": null, "data": {} },
    "cookies": { "..." : "..." },
    "cors": { "..." : "..." },
    "redirection": { "..." : "..." },
    "referrer-policy": { "..." : "..." },
    "hsts": { "..." : "..." },
    "sri": { "..." : "..." },
    "x-content-type-options": { "..." : "..." },
    "x-frame-options": { "..." : "..." },
    "corp": { "..." : "..." },
    "permissions-policy": { "..." : "..." }
  },
  "informational": {
    "coop": { "set": false, "value": null, "description": "..." },
    "coep": { "set": false, "value": null, "description": "..." },
    "infoLeakage": { "issues": [] }
  },
  "rawHeaders": { "content-type": "text/html", "..." : "..." },
  "summary": { "passCount": 9, "failCount": 2, "totalTests": 11 }
}
```

**Rate limit:** 20 scan requests per IP per hour.

**Example:**

```bash
# Step 1: Get a token
TOKEN=$(curl -s http://localhost:8788/api/token | jq -r '.token')

# Step 2: Run the scan
curl -X POST http://localhost:8788/api/scan \
  -H "Content-Type: application/json" \
  -d "{\"url\": \"https://example.com\", \"token\": \"$TOKEN\"}"
```

**Error responses:**

| Status | Meaning |
|--------|---------|
| 400 | Invalid URL or URL format |
| 403 | Invalid/expired token or disallowed origin |
| 408 | Target server did not respond within 8 seconds |
| 429 | Rate limit exceeded (20 scans/hour/IP) |
| 502 | Could not connect to target URL |
| 503 | Service misconfigured (missing SCAN_SECRET or RATE_LIMIT KV) |

## Configuration

| Variable | Purpose | Default |
|----------|---------|---------|
| `ALLOWED_ORIGINS` | Comma-separated list of allowed CORS origins | `*` |
| `SCAN_SECRET` | HMAC secret used to sign and verify tokens (set via `wrangler pages secret put`) | _(required)_ |
| `RATE_LIMIT` | KV namespace binding for per-IP rate limiting | _(required)_ |

### wrangler.toml

The `wrangler.toml` file configures the Cloudflare Pages project:

- `name` -- Project name used for deployment (`headers-checker`).
- `compatibility_date` -- Cloudflare Workers API compatibility date.
- `pages_build_output_dir` -- Points to the `demo/` directory, which contains the standalone demo UI.
- `[vars]` -- Default environment variables. Override these in the Cloudflare dashboard for production.
- `[[kv_namespaces]]` -- Uncomment and fill in your KV namespace ID after creating it with `wrangler kv namespace create RATE_LIMIT`.

## Deploy to Cloudflare

1. **Create a KV namespace** for rate limiting:

   ```bash
   wrangler kv namespace create RATE_LIMIT
   ```

   Copy the namespace ID from the output.

2. **Edit `wrangler.toml`** -- uncomment the `[[kv_namespaces]]` block and paste your namespace ID.

3. **Set the HMAC secret** used for token signing:

   ```bash
   wrangler pages secret put SCAN_SECRET
   ```

   Enter a random string when prompted (e.g., output of `openssl rand -hex 32`).

4. **Set `ALLOWED_ORIGINS`** in the Cloudflare dashboard (Pages > Settings > Environment variables) to your production domain (e.g., `https://yourdomain.com`).

5. **Deploy:**

   ```bash
   wrangler pages deploy demo --project-name=headers-checker
   ```

## Scoring Methodology

The scanner starts at a base score of 100 and applies modifiers from each test. Negative modifiers reduce the score; positive modifiers add bonus points. Bonus points are only applied if the base score (after all deductions) is >= 90. This prevents poorly configured sites from inflating their grade with a single strong header.

The final score maps to a 13-grade scale from A+ (100+) down to F (0-19).

Full details, weight tables, and worked examples are in [docs/scoring/headers.md](../docs/scoring/headers.md).

## Architecture

The serverless function (`functions/api/scan.js`) processes a scan request through these stages:

1. **Input validation** -- Parses and validates the URL. Blocks private/reserved IPs, localhost, and cloud metadata endpoints.
2. **SSRF protection** -- Resolves the domain via Cloudflare DNS-over-HTTPS and rejects domains pointing to private IP ranges (DNS rebinding defense).
3. **HMAC token verification** -- Validates the token was signed with the correct secret, is bound to the requester's IP, and is less than 5 minutes old. Uses timing-safe comparison.
4. **Rate limiting** -- Checks per-IP request count against Cloudflare KV (20 scans/hour, 3600s TTL).
5. **HTTP requests** -- Performs three requests in parallel:
   - HTTPS GET to the target URL (follows up to 10 redirects, captures up to 512 KB of response body for SRI analysis)
   - HTTP GET to test redirect behavior (3s timeout)
   - CORS probe with `Origin: https://evil.example.com` header
6. **Test execution** -- Runs all 11 scored tests plus informational checks against the response headers, cookies, and HTML body.
7. **Score calculation** -- Applies the Observatory v5 extra-credit gating algorithm and maps the result to a letter grade.

## License

MIT
