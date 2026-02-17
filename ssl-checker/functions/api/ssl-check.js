/**
 * SSL/TLS Certificate Checker API
 * Cloudflare Pages Function — POST /api/ssl-check
 *
 * Runs 8 SSL/TLS security tests via fetch + crt.sh + DoH
 * and returns a scored grade from A+ to F.
 */

// ── Constants ──

function getAllowedOrigins(env) {
  if (env && env.ALLOWED_ORIGINS) {
    return env.ALLOWED_ORIGINS.split(',').map(o => o.trim());
  }
  return ['*'];
}

const DOH_ENDPOINT = 'https://cloudflare-dns.com/dns-query';
const DOH_TIMEOUT_MS = 5000;
const CRTSH_TIMEOUT_MS = 3000;

// ── Grade Lookup (13-grade scale) ──

function scoreToGrade(score) {
  const clamped = Math.max(0, score);
  const bucket = Math.floor(clamped / 5) * 5;
  if (bucket >= 100) return 'A+';
  if (bucket >= 95) return 'A';
  if (bucket >= 90) return 'A';
  if (bucket >= 85) return 'A-';
  if (bucket >= 80) return 'B+';
  if (bucket >= 75) return 'B';
  if (bucket >= 70) return 'B';
  if (bucket >= 65) return 'B-';
  if (bucket >= 60) return 'C+';
  if (bucket >= 55) return 'C';
  if (bucket >= 50) return 'C';
  if (bucket >= 45) return 'C-';
  if (bucket >= 40) return 'D+';
  if (bucket >= 35) return 'D';
  if (bucket >= 30) return 'D';
  if (bucket >= 25) return 'D-';
  return 'F';
}

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

// ── DoH Query Helper ──

async function queryDoH(name, type) {
  const url = `${DOH_ENDPOINT}?name=${encodeURIComponent(name)}&type=${type}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DOH_TIMEOUT_MS);

  try {
    const res = await fetch(url, {
      headers: { 'Accept': 'application/dns-json' },
      signal: controller.signal,
    });
    if (!res.ok) return { Status: -1, Answer: [], AD: false };
    return await res.json();
  } catch {
    return { Status: -1, Answer: [], AD: false };
  } finally {
    clearTimeout(timer);
  }
}

// ── crt.sh Query Helper ──

async function queryCrtSh(domain) {
  const url = `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), CRTSH_TIMEOUT_MS);

  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { 'User-Agent': 'AppSecSanta-SSLChecker/1.0' },
    });
    if (!res.ok) return null;
    const data = await res.json();
    if (!Array.isArray(data)) return null;
    return data;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// ── Parse crt.sh data ──

function parseCertificateData(crtshData, domain) {
  if (!crtshData || crtshData.length === 0) return null;

  const now = new Date();

  // Filter for currently valid certs matching the domain
  const validCerts = crtshData.filter(cert => {
    const notAfter = new Date(cert.not_after);
    return notAfter > now;
  });

  if (validCerts.length === 0) return null;

  // Sort by not_before DESC (most recent first)
  validCerts.sort((a, b) => new Date(b.not_before) - new Date(a.not_before));

  const cert = validCerts[0];
  const notAfter = new Date(cert.not_after);
  const notBefore = new Date(cert.not_before);
  const daysRemaining = Math.floor((notAfter - now) / (1000 * 60 * 60 * 24));

  // Extract SANs from name_value
  const sans = cert.name_value ? cert.name_value.split('\n').filter(Boolean) : [];

  return {
    issuer: cert.issuer_name || '',
    validFrom: notBefore.toISOString().split('T')[0],
    validTo: notAfter.toISOString().split('T')[0],
    daysRemaining,
    commonName: cert.common_name || domain,
    sans,
    entryTimestamp: cert.entry_timestamp || null,
  };
}

// ── Test 1: HTTPS Available ──

function testHTTPS(httpsResult) {
  if (httpsResult.status === 'rejected') {
    return {
      pass: false,
      scoreModifier: -20,
      description: 'HTTPS connection failed. The site is not reachable over HTTPS.',
      recommendation: 'Install a valid SSL/TLS certificate. Free certificates are available from Let\'s Encrypt.',
    };
  }

  const res = httpsResult.value;
  if (res && res.ok) {
    return {
      pass: true,
      scoreModifier: 15,
      description: 'HTTPS is available and responding. The site serves content over an encrypted connection.',
      recommendation: null,
    };
  }

  // Got a response but not 2xx — still means HTTPS works
  if (res) {
    return {
      pass: true,
      scoreModifier: 15,
      description: `HTTPS is available (HTTP ${res.status}). The TLS connection was established successfully.`,
      recommendation: null,
    };
  }

  return {
    pass: false,
    scoreModifier: -20,
    description: 'HTTPS connection failed.',
    recommendation: 'Install a valid SSL/TLS certificate on your web server.',
  };
}

// ── Test 2: HTTP→HTTPS Redirect ──

function testRedirect(httpResult) {
  if (httpResult.status === 'rejected') {
    // HTTP not available at all — could be good (HTTPS-only) or just down
    return {
      pass: true,
      scoreModifier: 5,
      description: 'HTTP port does not respond. If HTTPS is working, this may indicate HTTP is disabled entirely.',
      recommendation: 'Consider configuring HTTP to redirect to HTTPS for users who type URLs without the protocol.',
    };
  }

  const res = httpResult.value;
  if (!res) {
    return {
      pass: null,
      scoreModifier: 0,
      description: 'HTTP redirect check could not be completed.',
      recommendation: null,
    };
  }

  const status = res.status;
  const location = res.headers.get('location') || '';

  if (status >= 300 && status < 400 && location.toLowerCase().startsWith('https://')) {
    return {
      pass: true,
      scoreModifier: 10,
      description: `HTTP redirects to HTTPS (${status} → ${location.split('/').slice(0, 3).join('/')}). Users are automatically upgraded to encrypted connections.`,
      recommendation: null,
    };
  }

  if (status >= 300 && status < 400) {
    return {
      pass: false,
      scoreModifier: -5,
      description: `HTTP redirects but not to HTTPS (${status} → ${location || 'unknown'}). Users may stay on unencrypted connections.`,
      recommendation: 'Configure your HTTP redirect to point to an HTTPS URL.',
    };
  }

  return {
    pass: false,
    scoreModifier: -10,
    description: `HTTP responds with status ${status} instead of redirecting to HTTPS. Unencrypted connections are served.`,
    recommendation: 'Add a 301 redirect from HTTP to HTTPS. In nginx: return 301 https://$host$request_uri;',
  };
}

// ── Test 3: HSTS Configuration ──

function testHSTS(httpsResult) {
  if (httpsResult.status === 'rejected') {
    return {
      pass: null,
      scoreModifier: 0,
      description: 'HSTS check could not be completed because HTTPS is unavailable.',
      recommendation: null,
    };
  }

  const res = httpsResult.value;
  if (!res) {
    return {
      pass: null,
      scoreModifier: 0,
      description: 'HSTS check could not be completed.',
      recommendation: null,
    };
  }

  const hsts = res.headers.get('strict-transport-security');
  if (!hsts) {
    return {
      pass: false,
      scoreModifier: -15,
      description: 'No HSTS header found. Browsers can be downgraded to HTTP via man-in-the-middle attacks.',
      recommendation: 'Add the Strict-Transport-Security header. Recommended: max-age=31536000; includeSubDomains; preload',
    };
  }

  const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
  const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
  const hasSubDomains = /includeSubDomains/i.test(hsts);
  const hasPreload = /preload/i.test(hsts);

  if (maxAge >= 31536000 && hasSubDomains && hasPreload) {
    return {
      pass: true,
      scoreModifier: 15,
      description: `HSTS is configured with max-age=${maxAge}, includeSubDomains, and preload. Browsers will enforce HTTPS for this domain.`,
      recommendation: null,
    };
  }

  if (maxAge >= 31536000 && hasSubDomains) {
    return {
      pass: true,
      scoreModifier: 12,
      description: `HSTS is configured with max-age=${maxAge} and includeSubDomains. Strong HTTPS enforcement.`,
      recommendation: 'Add the preload directive and submit to hstspreload.org for inclusion in browser preload lists.',
    };
  }

  if (maxAge >= 31536000) {
    return {
      pass: true,
      scoreModifier: 10,
      description: `HSTS is configured with max-age=${maxAge}. HTTPS is enforced after first visit.`,
      recommendation: 'Add includeSubDomains and preload for comprehensive protection.',
    };
  }

  if (maxAge > 0) {
    return {
      pass: true,
      scoreModifier: 5,
      description: `HSTS is configured but max-age is only ${maxAge} seconds (${Math.floor(maxAge / 86400)} days). This is shorter than recommended.`,
      recommendation: 'Increase max-age to at least 31536000 (1 year). Add includeSubDomains and preload.',
    };
  }

  return {
    pass: false,
    scoreModifier: -10,
    description: 'HSTS header found but max-age is 0 or invalid. HSTS is effectively disabled.',
    recommendation: 'Set max-age to at least 31536000 (1 year).',
  };
}

// ── Test 4: Certificate Expiry ──

function testCertExpiry(certData) {
  if (!certData) {
    return {
      pass: null,
      scoreModifier: 0,
      description: 'Certificate expiry check could not be completed (crt.sh unavailable).',
      recommendation: null,
    };
  }

  if (certData.daysRemaining <= 0) {
    return {
      pass: false,
      scoreModifier: -15,
      description: 'Certificate has expired! The certificate was valid until ' + certData.validTo + '.',
      recommendation: 'Renew your SSL/TLS certificate immediately. Consider using auto-renewal with Let\'s Encrypt or your CA.',
    };
  }

  if (certData.daysRemaining <= 7) {
    return {
      pass: false,
      scoreModifier: -10,
      description: `Certificate expires in ${certData.daysRemaining} day(s) (${certData.validTo}). Renewal is urgent.`,
      recommendation: 'Renew your certificate immediately. Set up auto-renewal to avoid future expiration.',
    };
  }

  if (certData.daysRemaining <= 30) {
    return {
      pass: false,
      scoreModifier: -5,
      description: `Certificate expires in ${certData.daysRemaining} days (${certData.validTo}). Renewal is due soon.`,
      recommendation: 'Renew your certificate soon. Let\'s Encrypt renews at 30 days by default.',
    };
  }

  return {
    pass: true,
    scoreModifier: 15,
    description: `Certificate is valid for ${certData.daysRemaining} more days (expires ${certData.validTo}). No immediate renewal needed.`,
    recommendation: null,
  };
}

// ── Test 5: Certificate Transparency ──

function testCertTransparency(crtshData, domain) {
  if (!crtshData) {
    return {
      pass: null,
      scoreModifier: 0,
      description: 'Certificate Transparency check could not be completed (crt.sh unavailable).',
      recommendation: null,
    };
  }

  if (crtshData.length === 0) {
    return {
      pass: false,
      scoreModifier: -10,
      description: 'No certificates found in Certificate Transparency logs for this domain.',
      recommendation: 'Ensure your CA logs certificates to CT logs. Most modern CAs do this by default.',
    };
  }

  const now = new Date();
  const validCerts = crtshData.filter(c => new Date(c.not_after) > now);

  return {
    pass: true,
    scoreModifier: 10,
    description: `${crtshData.length} certificate(s) found in CT logs (${validCerts.length} currently valid). Certificate issuance is publicly auditable.`,
    recommendation: null,
  };
}

// ── Test 6: Certificate Issuer ──

function testCertIssuer(certData) {
  if (!certData) {
    return {
      pass: null,
      scoreModifier: 0,
      description: 'Certificate issuer check could not be completed (crt.sh unavailable).',
      recommendation: null,
    };
  }

  const issuer = certData.issuer.toLowerCase();

  // Well-known CAs
  const trustedCAs = [
    'let\'s encrypt', 'letsencrypt', 'digicert', 'comodo', 'sectigo',
    'globalsign', 'godaddy', 'go daddy', 'entrust', 'thawte', 'geotrust',
    'rapidssl', 'symantec', 'verisign', 'amazon', 'cloudflare', 'google',
    'microsoft', 'apple', 'certum', 'buypass', 'ssl.com', 'zerossl',
    'actalis', 'trustwave', 'starfield', 'network solutions', 'usertrust',
    'isrg', 'baltimore', 'cybertrust', 'identrust',
  ];

  const isTrusted = trustedCAs.some(ca => issuer.includes(ca));

  // Extract readable issuer name
  const cnMatch = certData.issuer.match(/CN=([^,]+)/);
  const oMatch = certData.issuer.match(/O=([^,]+)/);
  const issuerName = cnMatch ? cnMatch[1] : (oMatch ? oMatch[1] : certData.issuer.slice(0, 60));

  if (isTrusted) {
    return {
      pass: true,
      scoreModifier: 10,
      description: `Certificate issued by ${issuerName}, a recognized Certificate Authority.`,
      recommendation: null,
    };
  }

  // Self-signed check
  if (issuer.includes('self-signed') || issuer.includes('self signed')) {
    return {
      pass: false,
      scoreModifier: -5,
      description: `Certificate appears to be self-signed (${issuerName}). Browsers will show security warnings.`,
      recommendation: 'Replace with a certificate from a trusted CA. Free certificates are available from Let\'s Encrypt.',
    };
  }

  return {
    pass: true,
    scoreModifier: 5,
    description: `Certificate issued by ${issuerName}.`,
    recommendation: 'Verify that your Certificate Authority is widely trusted by browsers and operating systems.',
  };
}

// ── Test 7: DANE/TLSA Records ──

function testDANE(tlsaResult) {
  if (tlsaResult.Status === -1) {
    return {
      pass: null,
      scoreModifier: 0,
      description: 'DANE/TLSA check could not be completed.',
      recommendation: null,
    };
  }

  // TLSA is DNS type 52
  const answers = (tlsaResult.Answer || []).filter(r => r.type === 52);

  if (answers.length > 0) {
    return {
      pass: true,
      scoreModifier: 10,
      description: `${answers.length} DANE/TLSA record(s) found. Certificate binding is enforced via DNS.`,
      recommendation: null,
    };
  }

  // DANE is a bonus — no penalty for missing it
  return {
    pass: null,
    scoreModifier: 0,
    description: 'No DANE/TLSA records found. This is an advanced DNS-based certificate binding mechanism — most domains don\'t use it yet.',
    recommendation: 'Consider adding TLSA records if you have DNSSEC enabled. This binds your certificate to DNS for extra assurance.',
  };
}

// ── Test 8: HTTPS Downgrade Protection ──

function testHTTPSDowngrade(httpsManualResult) {
  if (httpsManualResult.status === 'rejected') {
    return {
      pass: null,
      scoreModifier: 0,
      description: 'HTTPS downgrade check could not be completed because HTTPS is unavailable.',
      recommendation: null,
    };
  }

  const res = httpsManualResult.value;
  if (!res) {
    return {
      pass: null,
      scoreModifier: 0,
      description: 'HTTPS downgrade check could not be completed.',
      recommendation: null,
    };
  }

  const status = res.status;
  const location = (res.headers.get('location') || '').toLowerCase();

  // If HTTPS redirects to HTTP, that's a downgrade
  if (status >= 300 && status < 400 && location.startsWith('http://')) {
    return {
      pass: false,
      scoreModifier: -15,
      description: `HTTPS redirects to HTTP (${status} → ${location.split('/').slice(0, 3).join('/')}). This downgrades users from encrypted to unencrypted connections.`,
      recommendation: 'Remove the HTTP redirect from HTTPS responses. HTTPS should never downgrade to HTTP.',
    };
  }

  // No redirect, or redirect stays on HTTPS — good
  return {
    pass: true,
    scoreModifier: 10,
    description: 'HTTPS does not redirect to HTTP. Encrypted connections are maintained.',
    recommendation: null,
  };
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

// ── SSRF Protection: check domain doesn't resolve to private IP ──

async function resolvesDangerousIP(domain) {
  const result = await queryDoH(domain, 'A');
  const answers = (result.Answer || []).filter(r => r.type === 1);
  for (const record of answers) {
    const ip = (record.data || '').trim();
    if (isPrivateIP(ip)) return true;
  }
  return false;
}

function isPrivateIP(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(p => isNaN(p))) return false;
  // 10.0.0.0/8
  if (parts[0] === 10) return true;
  // 172.16.0.0/12
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  // 192.168.0.0/16
  if (parts[0] === 192 && parts[1] === 168) return true;
  // 127.0.0.0/8 (loopback)
  if (parts[0] === 127) return true;
  // 169.254.0.0/16 (link-local / cloud metadata)
  if (parts[0] === 169 && parts[1] === 254) return true;
  // 0.0.0.0/8
  if (parts[0] === 0) return true;
  return false;
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
    const key = `rl:ssl:${ip}`;
    try {
      const current = parseInt(await rateLimitKV.get(key) || '0', 10);
      if (current >= 20) {
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

  // ── SSRF Protection: reject domains that resolve to private IPs ──
  try {
    if (await resolvesDangerousIP(domain)) {
      return new Response(JSON.stringify({ error: 'Domain resolves to a private IP address.' }), {
        status: 400, headers: corsHeaders,
      });
    }
  } catch {
    // DoH failure — proceed cautiously (Cloudflare Workers block private IPs at fetch level)
  }

  // ── Run all checks in parallel ──
  let httpsResult, httpResult, httpsManualResult, crtshData, tlsaResult;

  try {
    const results = await Promise.allSettled([
      fetch('https://' + domain, {
        redirect: 'manual',
        headers: { 'User-Agent': 'AppSecSanta-SSLChecker/1.0' },
        signal: AbortSignal.timeout(8000),
      }),
      fetch('http://' + domain, {
        redirect: 'manual',
        headers: { 'User-Agent': 'AppSecSanta-SSLChecker/1.0' },
        signal: AbortSignal.timeout(5000),
      }),
      fetch('https://' + domain, {
        redirect: 'manual',
        headers: { 'User-Agent': 'AppSecSanta-SSLChecker/1.0' },
        signal: AbortSignal.timeout(5000),
      }),
      queryCrtSh(domain),
      queryDoH('_443._tcp.' + domain, 'TLSA'),
    ]);

    httpsResult = results[0];
    httpResult = results[1];
    httpsManualResult = results[2];
    // crt.sh returns data directly (not a Response), so handle allSettled wrapper
    crtshData = results[3].status === 'fulfilled' ? results[3].value : null;
    tlsaResult = results[4].status === 'fulfilled' ? results[4].value : { Status: -1, Answer: [] };
  } catch {
    return new Response(JSON.stringify({ error: 'SSL check failed. Please try again.' }), {
      status: 502, headers: corsHeaders,
    });
  }

  // Parse certificate data from crt.sh
  const certData = parseCertificateData(crtshData, domain);

  // ── Run all 8 tests ──
  const tests = {
    'https': testHTTPS(httpsResult),
    'redirect': testRedirect(httpResult),
    'hsts': testHSTS(httpsResult),
    'cert-expiry': testCertExpiry(certData),
    'cert-transparency': testCertTransparency(crtshData, domain),
    'cert-issuer': testCertIssuer(certData),
    'dane': testDANE(tlsaResult),
    'https-downgrade': testHTTPSDowngrade(httpsManualResult),
  };

  // ── Scoring ──
  let totalModifier = 0;
  let passCount = 0;

  for (const test of Object.values(tests)) {
    totalModifier += test.scoreModifier;
    if (test.pass === true) passCount++;
  }

  const score = Math.max(0, Math.min(100, 100 + totalModifier));
  const grade = scoreToGrade(score);

  // ── Build certificate info for display ──
  let certificateInfo = null;
  if (certData) {
    const cnMatch = certData.issuer.match(/CN=([^,]+)/);
    const oMatch = certData.issuer.match(/O=([^,]+)/);
    certificateInfo = {
      issuer: cnMatch ? cnMatch[1] : (oMatch ? oMatch[1] : certData.issuer.slice(0, 80)),
      validFrom: certData.validFrom,
      validTo: certData.validTo,
      daysRemaining: certData.daysRemaining,
      commonName: certData.commonName,
      sans: certData.sans.slice(0, 20),
    };
  }

  // ── Redirect chain info ──
  const httpRes = httpResult.status === 'fulfilled' ? httpResult.value : null;
  const httpsRes = httpsResult.status === 'fulfilled' ? httpsResult.value : null;
  const redirectChain = {
    httpToHttps: httpRes ? (httpRes.status >= 300 && httpRes.status < 400 && (httpRes.headers.get('location') || '').toLowerCase().startsWith('https://')) : false,
    httpStatus: httpRes ? httpRes.status : null,
    httpsStatus: httpsRes ? httpsRes.status : null,
  };

  // ── Response ──
  const result = {
    domain,
    grade,
    score,
    scannedAt: new Date().toISOString(),
    tests,
    certificateInfo,
    redirectChain,
    summary: {
      passCount,
      totalTests: Object.keys(tests).length,
    },
  };

  return new Response(JSON.stringify(result), { status: 200, headers: corsHeaders });

  } catch (err) {
    // Top-level catch prevents Cloudflare from returning its own HTML error page
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
