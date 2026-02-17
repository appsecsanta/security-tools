# SSL/TLS Checker

Runs 8 SSL/TLS security tests against a domain using HTTPS probes, Certificate Transparency logs (crt.sh), and DNS-over-HTTPS lookups, producing an A+ to F grade.

[Live Demo](https://appsecsanta.com/tools/ssl-checker) | [Scoring Methodology](../docs/scoring/ssl.md) | [Back to Catalog](../)

---

## What It Tests

| Test | Score Impact | What It Checks |
|------|-------------|----------------|
| HTTPS Available | -20 (failed) to +15 (responding) | Connects to the domain on port 443 with an 8-second timeout. Any successful TLS handshake passes, regardless of HTTP status code. |
| HTTP Redirect | -10 (serves HTTP content) to +10 (redirects to HTTPS) | Connects on port 80 with a 5-second timeout. Checks that the response is a 301/308 redirect pointing to an `https://` URL. |
| HSTS | -15 (missing) to +15 (preload-ready) | Reads the `Strict-Transport-Security` header from the HTTPS response. Scores based on `max-age` value, `includeSubDomains`, and `preload` directives. |
| Certificate Expiry | -15 (expired) to +15 (valid > 30 days) | Queries crt.sh for the most recent valid certificate and calculates days remaining until expiry. Flags certificates expiring within 7 or 30 days. |
| Certificate Transparency | -10 (no CT entries) to +10 (logged) | Queries crt.sh for all certificates issued for the domain. Verifies that certificates are publicly logged in CT logs. |
| Certificate Issuer | -5 (self-signed) to +10 (trusted CA) | Parses the issuer field from the most recent crt.sh certificate. Checks against a list of well-known CAs (Let's Encrypt, DigiCert, Cloudflare, etc.). |
| DANE/TLSA | 0 (not found) to +10 (present) | Queries DNS for `_443._tcp.<domain>` TLSA records (type 52). This is a bonus-only test with no penalty for missing records. |
| HTTPS Downgrade | -15 (downgrades) to +10 (maintained) | Makes an HTTPS request with `redirect: manual` and checks whether the response redirects to an `http://` URL, which would downgrade the connection. |

## Quick Start

```bash
git clone https://github.com/appsecsanta/security-tools.git
cd security-tools/ssl-checker
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

### POST /api/ssl-check

Runs 8 SSL/TLS security tests against the provided domain and returns scored results with certificate details.

**Request body:**

```json
{
  "domain": "example.com",
  "token": "<token-from-GET-/api/token>"
}
```

The `domain` field accepts bare domains, domains with protocol prefixes (stripped automatically), and domains with trailing paths or ports (also stripped).

**Response:**

```json
{
  "domain": "example.com",
  "grade": "A",
  "score": 95,
  "scannedAt": "2026-02-17T12:00:00.000Z",
  "tests": {
    "https": { "pass": true, "scoreModifier": 15, "description": "...", "recommendation": null },
    "redirect": { "pass": true, "scoreModifier": 10, "description": "...", "recommendation": null },
    "hsts": { "pass": true, "scoreModifier": 15, "description": "...", "recommendation": null },
    "cert-expiry": { "pass": true, "scoreModifier": 15, "description": "...", "recommendation": null },
    "cert-transparency": { "pass": true, "scoreModifier": 10, "description": "...", "recommendation": null },
    "cert-issuer": { "pass": true, "scoreModifier": 10, "description": "...", "recommendation": null },
    "dane": { "pass": null, "scoreModifier": 0, "description": "...", "recommendation": "..." },
    "https-downgrade": { "pass": true, "scoreModifier": 10, "description": "...", "recommendation": null }
  },
  "certificateInfo": {
    "issuer": "R3",
    "validFrom": "2026-01-01",
    "validTo": "2026-04-01",
    "daysRemaining": 43,
    "commonName": "example.com",
    "sans": ["example.com", "www.example.com"]
  },
  "redirectChain": {
    "httpToHttps": true,
    "httpStatus": 301,
    "httpsStatus": 200
  },
  "summary": { "passCount": 7, "totalTests": 8 }
}
```

**Rate limit:** 20 scan requests per IP per hour.

**Example:**

```bash
# Step 1: Get a token
TOKEN=$(curl -s http://localhost:8788/api/token | jq -r '.token')

# Step 2: Run the scan
curl -X POST http://localhost:8788/api/ssl-check \
  -H "Content-Type: application/json" \
  -d "{\"domain\": \"example.com\", \"token\": \"$TOKEN\"}"
```

**Error responses:**

| Status | Meaning |
|--------|---------|
| 400 | Invalid domain format, reserved domain, or domain resolves to private IP |
| 403 | Invalid/expired token or disallowed origin |
| 429 | Rate limit exceeded (20 scans/hour/IP) |
| 502 | SSL check failed (could not reach any external source) |
| 503 | Service misconfigured (missing SCAN_SECRET or RATE_LIMIT KV) |

## Configuration

| Variable | Purpose | Default |
|----------|---------|---------|
| `ALLOWED_ORIGINS` | Comma-separated list of allowed CORS origins | `*` |
| `SCAN_SECRET` | HMAC secret used to sign and verify tokens (set via `wrangler pages secret put`) | _(required)_ |
| `RATE_LIMIT` | KV namespace binding for per-IP rate limiting | _(required)_ |

### wrangler.toml

The `wrangler.toml` file configures the Cloudflare Pages project:

- `name` -- Project name (`ssl-checker`).
- `compatibility_date` -- Cloudflare Workers API compatibility date.
- `pages_build_output_dir` -- Points to the `demo/` directory containing the standalone UI.
- `[vars]` -- Default environment variables. Override in the Cloudflare dashboard for production.
- `[[kv_namespaces]]` -- Uncomment and fill in your KV namespace ID after creating it.

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

4. **Set `ALLOWED_ORIGINS`** in the Cloudflare dashboard (Pages > Settings > Environment variables) to your production domain.

5. **Deploy:**

   ```bash
   wrangler pages deploy demo --project-name=ssl-checker
   ```

## Scoring Methodology

The score starts at 100 and each test applies a positive or negative modifier. The final score is clamped to 0--100 and mapped to a letter grade. DANE/TLSA is a bonus-only test (no penalty for missing records) because adoption is still limited.

The heaviest-weighted tests are HTTPS availability (+15/-20), HSTS (+15/-15), Certificate Expiry (+15/-15), and HTTPS Downgrade protection (+10/-15). A site without HTTPS loses 20 points from the base immediately, which cascades because HSTS and downgrade checks also fail.

Full details, weight tables, and worked examples are in [docs/scoring/ssl.md](../docs/scoring/ssl.md).

## Architecture

The serverless function (`functions/api/ssl-check.js`) processes a scan request through these stages:

1. **Input validation** -- Strips protocol, path, and port from the input. Validates domain format and blocks reserved/internal domains.
2. **SSRF protection** -- Resolves the domain via Cloudflare DNS-over-HTTPS and rejects domains pointing to private IP ranges.
3. **HMAC token verification** -- Validates the token was signed with the correct secret, is bound to the requester's IP, and is less than 5 minutes old.
4. **Rate limiting** -- Checks per-IP request count against Cloudflare KV (20 scans/hour, 3600s TTL).
5. **Parallel checks** -- Fires 5 requests simultaneously using `Promise.allSettled`:
   - HTTPS fetch to `https://<domain>` (8s timeout) for availability and HSTS header
   - HTTP fetch to `http://<domain>` (5s timeout) for redirect testing
   - Second HTTPS fetch (5s timeout, `redirect: manual`) for downgrade detection
   - crt.sh JSON API query (3s timeout) for certificate data and CT log verification
   - DNS-over-HTTPS query for `_443._tcp.<domain>` TLSA records (5s timeout)
6. **Certificate parsing** -- Extracts the most recent valid certificate from crt.sh data, calculating days remaining, issuer, SANs, and validity dates.
7. **Test execution** -- Runs all 8 tests against the collected data.
8. **Score calculation** -- Sums all modifiers, clamps to 0--100, and maps to a letter grade.

## License

MIT
