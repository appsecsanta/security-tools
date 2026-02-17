# DNS Security Checker

Evaluates 8 DNS security properties of a domain using Cloudflare DNS-over-HTTPS lookups and produces an A+ to F grade.

[Live Demo](https://appsecsanta.com/tools/dns-security-checker) | [Scoring Methodology](../docs/scoring/dns.md) | [Back to Catalog](../)

---

## What It Tests

| Test | Score Impact | What It Checks |
|------|-------------|----------------|
| DNSSEC | -15 (disabled) to +15 (validated) | Queries the domain's A record and inspects the AD (Authenticated Data) flag from the resolver to determine if DNSSEC is validated. |
| CAA Records | -10 (missing) to +10 (present) | Looks for DNS type 257 (CAA) records that restrict which Certificate Authorities can issue certificates for the domain. |
| NS Redundancy | -5 (single NS) to +10 (multi-provider) | Counts nameservers and checks whether they span multiple provider domains. Awards full points for 2+ NS records from different providers. |
| SOA Configuration | -5 (missing) to +5 (well-configured) | Parses the SOA record and validates refresh, retry, expire, and minimum TTL values against RFC-recommended ranges. |
| SPF Record | -15 (missing or +all) to +15 (hard fail) | Checks for a `v=spf1` TXT record. Validates that exactly one SPF record exists and scores based on the qualifier: `-all` (best), `~all` (good), `?all` (weak), `+all` (dangerous). |
| DMARC Record | -15 (missing) to +15 (p=reject) | Queries the `_dmarc.` subdomain for a TXT record. Scores based on the policy: `reject` (best), `quarantine` (good), `none` (monitoring only). |
| MX Records | 0 (no email) to +10 (redundant) | Checks for mail exchanger records. Awards points for multiple MX records indicating mail delivery redundancy. |
| Dangling CNAME | -25 (dangling) to +10 (no risk) | Checks if any CNAME record on the domain points to a non-existent target (NXDOMAIN), which creates a subdomain takeover vulnerability. |

## Quick Start

```bash
git clone https://github.com/appsecsanta/security-tools.git
cd security-tools/dns-checker
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

### POST /api/dns-check

Runs 8 DNS security tests against the provided domain and returns scored results.

**Request body:**

```json
{
  "domain": "example.com",
  "token": "<token-from-GET-/api/token>"
}
```

The `domain` field accepts bare domains, domains with protocol prefixes (which are stripped), and domains with trailing paths or ports (also stripped).

**Response:**

```json
{
  "domain": "example.com",
  "grade": "A",
  "score": 95,
  "scannedAt": "2026-02-17T12:00:00.000Z",
  "tests": {
    "dnssec": { "pass": true, "scoreModifier": 15, "description": "...", "recommendation": null },
    "caa": { "pass": true, "scoreModifier": 10, "description": "...", "recommendation": null },
    "ns": { "pass": true, "scoreModifier": 10, "description": "...", "recommendation": null },
    "soa": { "pass": true, "scoreModifier": 5, "description": "...", "recommendation": null },
    "spf": { "pass": true, "scoreModifier": 15, "description": "...", "recommendation": null },
    "dmarc": { "pass": true, "scoreModifier": 15, "description": "...", "recommendation": null },
    "mx": { "pass": true, "scoreModifier": 10, "description": "...", "recommendation": null },
    "dangling-cname": { "pass": true, "scoreModifier": 10, "description": "...", "recommendation": null }
  },
  "rawRecords": {
    "A": [{ "name": "example.com", "ttl": 300, "data": "93.184.216.34" }],
    "AAAA": [],
    "NS": [{ "name": "example.com", "ttl": 86400, "data": "ns1.example.com" }],
    "MX": [],
    "TXT": [],
    "CAA": [],
    "SOA": [],
    "CNAME": []
  },
  "summary": { "passCount": 8, "totalTests": 8 }
}
```

**Rate limit:** 20 scan requests per IP per hour.

**Example:**

```bash
# Step 1: Get a token
TOKEN=$(curl -s http://localhost:8788/api/token | jq -r '.token')

# Step 2: Run the scan
curl -X POST http://localhost:8788/api/dns-check \
  -H "Content-Type: application/json" \
  -d "{\"domain\": \"example.com\", \"token\": \"$TOKEN\"}"
```

**Error responses:**

| Status | Meaning |
|--------|---------|
| 400 | Invalid domain format or reserved domain |
| 403 | Invalid/expired token or disallowed origin |
| 429 | Rate limit exceeded (20 scans/hour/IP) |
| 502 | DNS lookup failed |
| 503 | Service misconfigured (missing SCAN_SECRET or RATE_LIMIT KV) |

## Configuration

| Variable | Purpose | Default |
|----------|---------|---------|
| `ALLOWED_ORIGINS` | Comma-separated list of allowed CORS origins | `*` |
| `SCAN_SECRET` | HMAC secret used to sign and verify tokens (set via `wrangler pages secret put`) | _(required)_ |
| `RATE_LIMIT` | KV namespace binding for per-IP rate limiting | _(required)_ |

### wrangler.toml

The `wrangler.toml` file configures the Cloudflare Pages project:

- `name` -- Project name (`dns-checker`).
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
   wrangler pages deploy demo --project-name=dns-checker
   ```

## Scoring Methodology

The score starts at 100 and each test applies a positive or negative modifier. Passing tests award bonus points; failing tests deduct points. The final score is clamped to a 0--100 range and mapped to a letter grade on the same 13-grade scale used across all tools (A+ through F).

The heaviest-weighted tests are DNSSEC (+/-15), SPF (+/-15), DMARC (+/-15), and Dangling CNAME (+10/-25). A domain missing all three email authentication records (SPF, DMARC, DNSSEC) loses 45 points immediately.

Full details, weight tables, and worked examples are in [docs/scoring/dns.md](../docs/scoring/dns.md).

## Architecture

The serverless function (`functions/api/dns-check.js`) processes a scan request through these stages:

1. **Input validation** -- Strips protocol, path, and port from the input. Validates domain format and blocks reserved/internal domains (localhost, metadata endpoints, example.com).
2. **HMAC token verification** -- Validates the token was signed with the correct secret, is bound to the requester's IP, and is less than 5 minutes old. Uses timing-safe comparison.
3. **Rate limiting** -- Checks per-IP request count against Cloudflare KV (20 scans/hour, 3600s TTL).
4. **DNS queries** -- Fires 9 parallel DNS-over-HTTPS queries to Cloudflare's resolver (`cloudflare-dns.com/dns-query`) requesting A, AAAA, NS, SOA, TXT, MX, CAA, CNAME records for the domain, plus a TXT query for `_dmarc.<domain>`. Each query has a 5-second timeout.
5. **Test execution** -- Runs all 8 scored tests against the query results. The Dangling CNAME test performs an additional DoH lookup to verify whether the CNAME target resolves.
6. **Score calculation** -- Sums all modifiers, clamps to 0--100, and maps to a letter grade.
7. **Response** -- Returns test results, raw DNS records (grouped by type), and the overall grade.

## License

MIT
