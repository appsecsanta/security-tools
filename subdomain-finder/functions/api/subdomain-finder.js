/**
 * Subdomain Finder API
 * Cloudflare Pages Function — POST /api/subdomain-finder
 *
 * Queries multiple sources (crt.sh, HackerTarget, Anubis) in parallel
 * to discover subdomains for a given domain. Results are cached in KV.
 */

// ── Constants ──

function getAllowedOrigins(env) {
  if (env && env.ALLOWED_ORIGINS) {
    return env.ALLOWED_ORIGINS.split(',').map(o => o.trim());
  }
  return ['*'];
}

const CRTSH_TIMEOUT_MS = 15000;
const SOURCE_TIMEOUT_MS = 8000;
const MAX_SUBDOMAINS = 500;
const MAX_RESPONSE_BYTES = 10 * 1024 * 1024; // 10MB cap on crt.sh response
const CACHE_TTL = 21600; // 6 hours in seconds

// ── Domain Validation ──

function validateDomain(input) {
  if (!input || typeof input !== 'string') {
    return { valid: false, error: 'Domain is required.' };
  }

  let raw = input.trim().toLowerCase();
  raw = raw.replace(/^https?:\/\//, '');
  raw = raw.replace(/\/.*$/, '');
  raw = raw.replace(/:\d+$/, '');

  if (!raw || !raw.includes('.')) {
    return { valid: false, error: 'Invalid domain. Enter a domain like example.com.' };
  }

  const domainRegex = /^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/;
  if (!domainRegex.test(raw)) {
    return { valid: false, error: 'Invalid domain format.' };
  }

  const blocked = [
    'localhost', 'localhost.localdomain', 'example.com', 'example.net', 'example.org',
    'metadata.google.internal', 'metadata.goog', 'instance-data.ec2.internal',
    'kubernetes.default.svc', 'kubernetes.default', 'metadata.internal',
  ];
  if (blocked.includes(raw) || blocked.some(b => raw.endsWith('.' + b))) {
    return { valid: false, error: 'Cannot scan reserved domains.' };
  }

  return { valid: true, domain: raw };
}

// ── HMAC Token Verification ──

async function verifyToken(token, ip, secret) {
  if (!token || typeof token !== 'string') return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;

  const timestamp = parseInt(parts[0], 10);
  if (isNaN(timestamp)) return false;

  const age = Date.now() - timestamp;
  if (age < 0 || age > 5 * 60 * 1000) return false;

  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(timestamp + ':' + ip)
  );
  const expected = Array.from(new Uint8Array(signature))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  const verifyKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode('hmac-compare'),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const [a, b] = await Promise.all([
    crypto.subtle.sign('HMAC', verifyKey, new TextEncoder().encode(expected)),
    crypto.subtle.sign('HMAC', verifyKey, new TextEncoder().encode(parts[1])),
  ]);
  const arrA = new Uint8Array(a);
  const arrB = new Uint8Array(b);
  if (arrA.length !== arrB.length) return false;
  let diff = 0;
  for (let i = 0; i < arrA.length; i++) {
    diff |= arrA[i] ^ arrB[i];
  }
  return diff === 0;
}

// ── crt.sh Query ──

async function queryCrtSh(domain) {
  const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json&deduplicate=Y`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), CRTSH_TIMEOUT_MS);

  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { 'User-Agent': 'AppSecSanta-SubdomainFinder/1.0' },
    });
    if (!res.ok) return { error: null, data: null };

    const contentLength = parseInt(res.headers.get('Content-Length') || '0', 10);
    if (contentLength > MAX_RESPONSE_BYTES) {
      return { error: 'too_large', data: null };
    }

    const text = await res.text();
    if (text.length > MAX_RESPONSE_BYTES) {
      return { error: 'too_large', data: null };
    }

    const data = JSON.parse(text);
    if (!Array.isArray(data)) return { error: null, data: null };
    return { error: null, data: data };
  } catch {
    return { error: null, data: null };
  } finally {
    clearTimeout(timer);
  }
}

// ── HackerTarget Query ──

async function queryHackerTarget(domain) {
  const url = `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), SOURCE_TIMEOUT_MS);

  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { 'User-Agent': 'AppSecSanta-SubdomainFinder/1.0' },
    });
    if (!res.ok) return [];

    const text = await res.text();
    // HackerTarget returns "error ..." on failures or rate limits
    if (!text || text.startsWith('error')) return [];

    const results = [];
    for (const line of text.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      // Format: subdomain,IP
      const comma = trimmed.indexOf(',');
      const name = (comma > 0 ? trimmed.substring(0, comma) : trimmed).toLowerCase();
      if (name && name.includes('.')) {
        results.push({ name });
      }
    }
    return results;
  } catch {
    return [];
  } finally {
    clearTimeout(timer);
  }
}

// ── Anubis Query ──

async function queryAnubis(domain) {
  const url = `https://jldc.me/anubis/subdomains/${encodeURIComponent(domain)}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), SOURCE_TIMEOUT_MS);

  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { 'User-Agent': 'AppSecSanta-SubdomainFinder/1.0' },
    });
    if (!res.ok) return [];

    const data = await res.json();
    if (!Array.isArray(data)) return [];

    return data
      .filter(name => typeof name === 'string' && name.includes('.'))
      .map(name => ({ name: name.toLowerCase() }));
  } catch {
    return [];
  } finally {
    clearTimeout(timer);
  }
}

// ── Parse Subdomains from crt.sh Data ──

function parseCrtShSubdomains(crtshData, domain) {
  const subdomainMap = new Map();
  const domainLower = domain.toLowerCase();

  for (const cert of crtshData) {
    const names = [];
    if (cert.common_name) names.push(cert.common_name);
    if (cert.name_value) {
      for (const name of cert.name_value.split('\n')) {
        const trimmed = name.trim();
        if (trimmed) names.push(trimmed);
      }
    }

    const notBefore = cert.not_before || '';
    const notAfter = cert.not_after || '';

    for (const rawName of names) {
      const name = rawName.toLowerCase().trim();

      if (name.startsWith('*.') || name.includes('*')) continue;
      if (name !== domainLower && !name.endsWith('.' + domainLower)) continue;

      if (subdomainMap.has(name)) {
        const entry = subdomainMap.get(name);
        entry.certCount++;
        if (notBefore && notBefore < entry.firstSeen) entry.firstSeen = notBefore;
        if (notAfter && notAfter > entry.lastSeen) entry.lastSeen = notAfter;
      } else {
        subdomainMap.set(name, {
          name,
          firstSeen: notBefore || '',
          lastSeen: notAfter || '',
          certCount: 1,
        });
      }
    }
  }

  return subdomainMap;
}

// ── Merge Subdomains from All Sources ──

function mergeSubdomains(crtshData, hackerTargetData, anubisData, domain) {
  const domainLower = domain.toLowerCase();

  // Start with crt.sh data (has rich metadata)
  const merged = crtshData ? parseCrtShSubdomains(crtshData, domain) : new Map();

  // Add HackerTarget and Anubis results (only if not already in crt.sh)
  const extraSources = [...hackerTargetData, ...anubisData];
  for (const entry of extraSources) {
    const name = entry.name.toLowerCase();

    if (name.startsWith('*.') || name.includes('*')) continue;
    if (name !== domainLower && !name.endsWith('.' + domainLower)) continue;

    if (!merged.has(name)) {
      merged.set(name, {
        name,
        firstSeen: '',
        lastSeen: '',
        certCount: 0,
      });
    }
  }

  // Sort alphabetically and cap
  const sorted = Array.from(merged.values())
    .sort((a, b) => a.name.localeCompare(b.name))
    .slice(0, MAX_SUBDOMAINS);

  // Format dates to YYYY-MM-DD
  for (const entry of sorted) {
    if (entry.firstSeen) entry.firstSeen = entry.firstSeen.split('T')[0];
    if (entry.lastSeen) entry.lastSeen = entry.lastSeen.split('T')[0];
  }

  return sorted;
}

// ── Main Handler ──

export async function onRequestPost(context) {
  const { request } = context;

  const origin = request.headers.get('Origin') || '';
  const allowedOrigins = getAllowedOrigins(context.env);
  const corsOrigin = allowedOrigins.includes(origin) ? origin : allowedOrigins[0];

  const corsHeaders = {
    'Access-Control-Allow-Origin': corsOrigin,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type': 'application/json',
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store',
  };

  try {
    // ── Hard Origin Gate ──
    const referer = request.headers.get('Referer') || '';
    const isAllowedOrigin = allowedOrigins.includes(origin)
      || allowedOrigins.some(o => referer.startsWith(o));
    if (!isAllowedOrigin) {
      return new Response(JSON.stringify({ error: 'Forbidden.' }), {
        status: 403, headers: corsHeaders,
      });
    }

    // Parse body
    let body;
    try {
      body = await request.json();
    } catch {
      return new Response(JSON.stringify({ error: 'Invalid JSON body.' }), { status: 400, headers: corsHeaders });
    }

    // ── Token Validation (fail closed) ──
    const scanSecret = context.env.SCAN_SECRET;
    if (!scanSecret) {
      return new Response(JSON.stringify({ error: 'Service misconfigured.' }), {
        status: 503, headers: corsHeaders,
      });
    }
    {
      const ip = request.headers.get('CF-Connecting-IP') || '';
      const valid = await verifyToken(body.token, ip, scanSecret);
      if (!valid) {
        return new Response(JSON.stringify({ error: 'Forbidden.' }), {
          status: 403, headers: corsHeaders,
        });
      }
    }

    // ── Rate Limiting (fail closed) ──
    const rateLimitKV = context.env.RATE_LIMIT;
    if (!rateLimitKV) {
      return new Response(JSON.stringify({ error: 'Service misconfigured.' }), {
        status: 503, headers: corsHeaders,
      });
    }
    {
      const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
      const key = `rl:subdomain:${ip}`;
      try {
        const current = parseInt(await rateLimitKV.get(key) || '0', 10);
        if (current >= 15) {
          return new Response(JSON.stringify({ error: 'Rate limit exceeded. Try again later.' }), {
            status: 429, headers: corsHeaders,
          });
        }
        await rateLimitKV.put(key, String(current + 1), { expirationTtl: 3600 });
      } catch {
        return new Response(JSON.stringify({ error: 'Rate limit check failed. Try again.' }), {
          status: 503, headers: corsHeaders,
        });
      }
    }

    // Validate domain
    const validation = validateDomain(body.domain);
    if (!validation.valid) {
      return new Response(JSON.stringify({ error: validation.error }), { status: 400, headers: corsHeaders });
    }

    const domain = validation.domain;

    // ── Check KV Cache ──
    const cacheKey = `cache:sub:${domain}`;
    try {
      const cached = await rateLimitKV.get(cacheKey);
      if (cached) {
        return new Response(cached, { status: 200, headers: corsHeaders });
      }
    } catch {
      // Cache miss or error — proceed with live queries
    }

    // ── Query All Sources in Parallel ──
    const [crtshResult, hackerTargetResult, anubisResult] = await Promise.allSettled([
      queryCrtSh(domain),
      queryHackerTarget(domain),
      queryAnubis(domain),
    ]);

    const crtsh = crtshResult.status === 'fulfilled' ? crtshResult.value : { error: null, data: null };
    const hackerTarget = hackerTargetResult.status === 'fulfilled' ? hackerTargetResult.value : [];
    const anubis = anubisResult.status === 'fulfilled' ? anubisResult.value : [];

    // crt.sh too_large is still a hard error — other sources can't compensate for huge domains
    if (crtsh.error === 'too_large') {
      return new Response(JSON.stringify({
        error: 'This domain has too many certificates to process. Try scanning a more specific subdomain (e.g. app.' + domain + ').',
      }), { status: 400, headers: corsHeaders });
    }

    const crtshData = crtsh.data;
    const hasAnySources = crtshData || hackerTarget.length > 0 || anubis.length > 0;

    if (!hasAnySources) {
      return new Response(JSON.stringify({
        error: 'Could not reach any subdomain data sources. Please try again in a moment.',
      }), { status: 502, headers: corsHeaders });
    }

    // ── Merge & Deduplicate ──
    const subdomains = mergeSubdomains(crtshData, hackerTarget, anubis, domain);

    // Track which sources contributed data
    const sources = [];
    if (crtshData && crtshData.length > 0) sources.push('crt.sh');
    if (hackerTarget.length > 0) sources.push('hackertarget');
    if (anubis.length > 0) sources.push('anubis');

    if (subdomains.length === 0) {
      const emptyResult = JSON.stringify({
        domain,
        scannedAt: new Date().toISOString(),
        subdomains: [],
        summary: {
          uniqueCount: 0,
          totalCertificates: 0,
          dateRange: { earliest: null, latest: null },
          sources,
        },
      });
      return new Response(emptyResult, { status: 200, headers: corsHeaders });
    }

    // Build summary
    let earliest = null;
    let latest = null;
    for (const sub of subdomains) {
      if (sub.firstSeen && (!earliest || sub.firstSeen < earliest)) earliest = sub.firstSeen;
      if (sub.lastSeen && (!latest || sub.lastSeen > latest)) latest = sub.lastSeen;
    }

    const result = {
      domain,
      scannedAt: new Date().toISOString(),
      subdomains,
      summary: {
        uniqueCount: subdomains.length,
        totalCertificates: crtshData ? crtshData.length : 0,
        dateRange: { earliest, latest },
        sources,
      },
    };

    const resultJson = JSON.stringify(result);

    // ── Store in KV Cache ──
    try {
      await rateLimitKV.put(cacheKey, resultJson, { expirationTtl: CACHE_TTL });
    } catch {
      // Cache write failure is non-fatal
    }

    return new Response(resultJson, { status: 200, headers: corsHeaders });

  } catch (err) {
    // Top-level catch prevents Cloudflare from returning its own HTML 502
    return new Response(JSON.stringify({
      error: 'An unexpected error occurred. Please try again.',
    }), { status: 500, headers: corsHeaders });
  }
}

// ── CORS preflight ──

export async function onRequestOptions(context) {
  const origin = context.request.headers.get('Origin') || '';
  const allowedOrigins = getAllowedOrigins(context.env);
  if (!allowedOrigins.includes(origin)) {
    return new Response(null, { status: 204 });
  }
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Max-Age': '86400',
    },
  });
}
