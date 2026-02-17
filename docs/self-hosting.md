# Self-Hosting Guide

Deploy the security tools on your own Cloudflare account using Workers/Pages.

## Prerequisites

- [Node.js](https://nodejs.org/) v18+
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update/) v3+
- A [Cloudflare account](https://dash.cloudflare.com/sign-up) (free tier works)

```bash
npm install -g wrangler
wrangler login
```

## Deploy a Single Tool

Example: deploying the headers checker.

```bash
# 1. Clone the repo
git clone https://github.com/appsecsanta/security-tools.git
cd security-tools/headers-checker

# 2. Create a KV namespace for rate limiting
wrangler kv namespace create RATE_LIMIT
# Note the ID from the output

# 3. Update wrangler.toml with the KV namespace ID
# [[kv_namespaces]]
# binding = "RATE_LIMIT"
# id = "<your-namespace-id>"

# 4. Deploy
wrangler pages deploy --project-name=headers-checker
```

Your tool is now live at `https://headers-checker.pages.dev`.

## Deploy All Tools

```bash
cd security-tools

for tool in headers-checker dns-checker ssl-checker subdomain-finder; do
  echo "Deploying $tool..."
  cd "$tool"
  wrangler kv namespace create RATE_LIMIT
  wrangler pages deploy --project-name="$tool"
  cd ..
done
```

Update each tool's `wrangler.toml` with its KV namespace ID before deploying.

## Custom Domain Setup

1. Go to the [Cloudflare dashboard](https://dash.cloudflare.com/) > Pages > your project > Custom domains.
2. Add your domain (e.g., `headers.yourdomain.com`).
3. Cloudflare will create a CNAME record automatically if the domain is on Cloudflare DNS.
4. For external DNS, create a CNAME pointing to `<project-name>.pages.dev`.

## Environment Variables

Set these in the Cloudflare dashboard under Pages > Settings > Environment variables, or in `wrangler.toml`.

| Variable | Description | Default |
|----------|-------------|---------|
| `ALLOWED_ORIGINS` | Comma-separated list of allowed CORS origins | `*` |
| `SCAN_SECRET` | Optional API key required in the `Authorization` header | _(none)_ |

### Setting via CLI

```bash
wrangler pages secret put SCAN_SECRET
# Enter your secret when prompted
```

### Using SCAN_SECRET

When `SCAN_SECRET` is set, all API requests must include:

```
Authorization: Bearer <your-scan-secret>
```

Requests without a valid token receive a `401 Unauthorized` response.

## Rate Limiting with KV

Each tool uses Cloudflare KV to track request counts per IP address. The default configuration:

- **Window:** 60 seconds
- **Max requests:** 10 per window per IP

Rate-limited requests receive a `429 Too Many Requests` response with a `Retry-After` header.

To adjust limits, modify the constants at the top of each API function:

```js
const RATE_LIMIT_WINDOW = 60;   // seconds
const RATE_LIMIT_MAX = 10;      // requests per window
```

KV keys expire automatically, so no cleanup is needed.

## Local Development

```bash
cd headers-checker  # or any tool directory
npm install
wrangler pages dev
```

This starts a local server at `http://localhost:8788` with:
- Hot reloading on file changes
- Local KV simulation (in-memory, resets on restart)
- Pages Functions routing

To test an API endpoint:

```bash
curl "http://localhost:8788/api/scan?url=https://example.com"
```

### Local Development without KV

If you don't need rate limiting during development, you can skip the KV namespace setup. The tools handle missing KV bindings gracefully and disable rate limiting when the binding is unavailable.
