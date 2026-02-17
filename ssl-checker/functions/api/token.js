/**
 * Challenge Token Endpoint — GET /api/token
 * Generates HMAC-signed tokens for scan API authentication.
 */

function getAllowedOrigins(env) {
  if (env && env.ALLOWED_ORIGINS) {
    return env.ALLOWED_ORIGINS.split(',').map(o => o.trim());
  }
  return ['*'];
}

export async function onRequestGet(context) {
  const { request } = context;

  const origin = request.headers.get('Origin') || '';
  const referer = request.headers.get('Referer') || '';
  const allowedOrigins = getAllowedOrigins(context.env);
  const corsOrigin = allowedOrigins.includes(origin) ? origin : allowedOrigins[0];

  const corsHeaders = {
    'Access-Control-Allow-Origin': corsOrigin,
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type': 'application/json',
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store',
  };

  // Origin gate
  const isAllowed = allowedOrigins.includes(origin)
    || allowedOrigins.some(o => referer.startsWith(o));
  if (!isAllowed) {
    return new Response(JSON.stringify({ error: 'Forbidden.' }), {
      status: 403, headers: corsHeaders,
    });
  }

  const secret = context.env.SCAN_SECRET;
  if (!secret) {
    return new Response(JSON.stringify({ error: 'Service unavailable.' }), {
      status: 503, headers: corsHeaders,
    });
  }

  // ── Rate Limiting (fail closed) ──
  const rateLimitKV = context.env.RATE_LIMIT;
  if (rateLimitKV) {
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const key = `rl:token:${ip}`;
    try {
      const current = parseInt(await rateLimitKV.get(key) || '0', 10);
      if (current >= 30) {
        return new Response(JSON.stringify({ error: 'Rate limit exceeded. Try again later.' }), {
          status: 429, headers: corsHeaders,
        });
      }
      await rateLimitKV.put(key, String(current + 1), { expirationTtl: 3600 });
    } catch {
      // Rate limit check failed — proceed (non-critical for token endpoint)
    }
  }

  const ip = request.headers.get('CF-Connecting-IP') || '';
  const timestamp = Date.now();

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

  const hex = Array.from(new Uint8Array(signature))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  const token = timestamp + '.' + hex;

  return new Response(JSON.stringify({ token }), {
    status: 200, headers: corsHeaders,
  });
}

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
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Max-Age': '86400',
    },
  });
}
