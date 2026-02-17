# Subdomain Finder

Discovers subdomains for a given domain by querying Certificate Transparency logs (crt.sh), HackerTarget, and Anubis in parallel, returning deduplicated results with certificate metadata.

[Live Demo](https://appsecsanta.com/tools/subdomain-finder) | [Back to Catalog](../)

---

## What It Finds

The tool aggregates subdomain data from three independent sources:

| Source | Method | What It Returns |
|--------|--------|-----------------|
| [crt.sh](https://crt.sh) | Certificate Transparency log search | Subdomains from SSL/TLS certificates, with first-seen/last-seen dates and certificate count per subdomain. Wildcard entries are excluded. |
| [HackerTarget](https://hackertarget.com) | DNS host search API | Subdomains discovered through passive DNS data. Returns subdomain names only (no metadata). |
| [Anubis](https://jldc.me/anubis/) | Subdomain enumeration API | Subdomains aggregated from multiple OSINT sources. Returns subdomain names only. |

Results are merged, deduplicated by hostname, sorted alphabetically, and capped at 500 entries. Cached results are served for 6 hours.

## Quick Start

```bash
git clone https://github.com/appsecsanta/security-tools.git
cd security-tools/subdomain-finder
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

### POST /api/subdomain-finder

Discovers subdomains for the provided domain by querying all three sources in parallel.

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
  "scannedAt": "2026-02-17T12:00:00.000Z",
  "subdomains": [
    {
      "name": "api.example.com",
      "firstSeen": "2024-03-15",
      "lastSeen": "2026-09-20",
      "certCount": 4
    },
    {
      "name": "mail.example.com",
      "firstSeen": "2023-01-10",
      "lastSeen": "2026-07-01",
      "certCount": 2
    },
    {
      "name": "staging.example.com",
      "firstSeen": "",
      "lastSeen": "",
      "certCount": 0
    }
  ],
  "summary": {
    "uniqueCount": 3,
    "totalCertificates": 42,
    "dateRange": {
      "earliest": "2023-01-10",
      "latest": "2026-09-20"
    },
    "sources": ["crt.sh", "hackertarget", "anubis"]
  }
}
```

Subdomains found only via HackerTarget or Anubis (not in crt.sh) have empty `firstSeen`/`lastSeen` fields and a `certCount` of 0.

**Rate limit:** 15 scan requests per IP per hour.

**Example:**

```bash
# Step 1: Get a token
TOKEN=$(curl -s http://localhost:8788/api/token | jq -r '.token')

# Step 2: Run the scan
curl -X POST http://localhost:8788/api/subdomain-finder \
  -H "Content-Type: application/json" \
  -d "{\"domain\": \"example.com\", \"token\": \"$TOKEN\"}"
```

**Error responses:**

| Status | Meaning |
|--------|---------|
| 400 | Invalid domain format, reserved domain, or domain has too many certificates to process |
| 403 | Invalid/expired token or disallowed origin |
| 429 | Rate limit exceeded (15 scans/hour/IP) |
| 502 | Could not reach any subdomain data source |
| 503 | Service misconfigured (missing SCAN_SECRET or RATE_LIMIT KV) |

## Configuration

| Variable | Purpose | Default |
|----------|---------|---------|
| `ALLOWED_ORIGINS` | Comma-separated list of allowed CORS origins | `*` |
| `SCAN_SECRET` | HMAC secret used to sign and verify tokens (set via `wrangler pages secret put`) | _(required)_ |
| `RATE_LIMIT` | KV namespace binding for rate limiting and result caching | _(required)_ |

### wrangler.toml

The `wrangler.toml` file configures the Cloudflare Pages project:

- `name` -- Project name (`subdomain-finder`).
- `compatibility_date` -- Cloudflare Workers API compatibility date.
- `pages_build_output_dir` -- Points to the `demo/` directory containing the standalone UI.
- `[vars]` -- Default environment variables. Override in the Cloudflare dashboard for production.
- `[[kv_namespaces]]` -- Uncomment and fill in your KV namespace ID after creating it.

**Note:** The KV namespace serves double duty for this tool: it stores both rate-limiting counters (1-hour TTL) and cached scan results (6-hour TTL) under separate key prefixes (`rl:subdomain:` and `cache:sub:` respectively).

## Deploy to Cloudflare

1. **Create a KV namespace** for rate limiting and caching:

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
   wrangler pages deploy demo --project-name=subdomain-finder
   ```

## Architecture

The serverless function (`functions/api/subdomain-finder.js`) processes a scan request through these stages:

1. **Input validation** -- Strips protocol, path, and port from the input. Validates domain format and blocks reserved/internal domains.
2. **HMAC token verification** -- Validates the token was signed with the correct secret, is bound to the requester's IP, and is less than 5 minutes old.
3. **Rate limiting** -- Checks per-IP request count against Cloudflare KV (15 scans/hour, 3600s TTL).
4. **Cache lookup** -- Checks KV for a cached result under `cache:sub:<domain>`. If found, returns the cached response immediately (6-hour TTL).
5. **Parallel source queries** -- Fires 3 requests simultaneously using `Promise.allSettled`:
   - **crt.sh** -- Queries `crt.sh/?q=%25.<domain>&output=json&deduplicate=Y` with a 15-second timeout and a 10 MB response size cap. Returns certificate metadata including common names, SANs, validity dates, and issuance timestamps.
   - **HackerTarget** -- Queries `api.hackertarget.com/hostsearch/?q=<domain>` with an 8-second timeout. Parses the CSV response format (`subdomain,IP`).
   - **Anubis** -- Queries `jldc.me/anubis/subdomains/<domain>` with an 8-second timeout. Parses the JSON array response.
6. **Merge and deduplication** -- Combines results from all sources. crt.sh entries carry certificate metadata (first-seen, last-seen, cert count). HackerTarget and Anubis entries are added with empty metadata if not already present from crt.sh. Wildcard entries (`*.example.com`) are excluded. Results are sorted alphabetically and capped at 500.
7. **Cache write** -- Stores the result in KV with a 6-hour TTL for subsequent requests.

## License

MIT
