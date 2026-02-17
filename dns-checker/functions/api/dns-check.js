/**
 * DNS Security Checker API
 * Cloudflare Pages Function — POST /api/dns-check
 *
 * Runs 8 DNS security tests via Cloudflare DoH and returns
 * a scored grade from A+ to F.
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

// ── Grade Lookup (13-grade scale, same as headers checker) ──

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

  // Strip protocol if provided
  raw = raw.replace(/^https?:\/\//, '');
  // Strip trailing path/slash
  raw = raw.replace(/\/.*$/, '');
  // Strip port
  raw = raw.replace(/:\d+$/, '');

  if (!raw || !raw.includes('.')) {
    return { valid: false, error: 'Invalid domain. Enter a domain like example.com.' };
  }

  // Basic domain validation
  const domainRegex = /^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/;
  if (!domainRegex.test(raw)) {
    return { valid: false, error: 'Invalid domain format.' };
  }

  // Block private/reserved
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

// ── Test 1: DNSSEC ──

function testDNSSEC(aResult) {
  if (aResult.Status === -1) {
    return {
      pass: null,
      scoreModifier: 0,
      description: 'DNSSEC check could not be completed.',
      recommendation: 'Try scanning again.',
    };
  }

  if (aResult.AD === true) {
    return {
      pass: true,
      scoreModifier: 15,
      description: 'DNSSEC is enabled and validated (AD flag set). DNS responses are authenticated.',
      recommendation: null,
    };
  }

  return {
    pass: false,
    scoreModifier: -15,
    description: 'DNSSEC is not enabled. DNS responses can be spoofed by attackers.',
    recommendation: 'Enable DNSSEC with your domain registrar and DNS provider. This cryptographically signs DNS records to prevent tampering.',
  };
}

// ── Test 2: CAA Records ──

function testCAA(caaResult) {
  const answers = (caaResult.Answer || []).filter(r => r.type === 257);

  if (answers.length === 0) {
    return {
      pass: false,
      scoreModifier: -10,
      description: 'No CAA records found. Any Certificate Authority can issue certificates for this domain.',
      recommendation: 'Add CAA records to restrict which CAs can issue certificates. Example: 0 issue "letsencrypt.org"',
    };
  }

  return {
    pass: true,
    scoreModifier: 10,
    description: `${answers.length} CAA record(s) found. Certificate issuance is restricted to authorized CAs.`,
    recommendation: null,
  };
}

// ── Test 3: Nameserver Redundancy ──

function testNS(nsResult) {
  const answers = (nsResult.Answer || []).filter(r => r.type === 2);
  const nsNames = answers.map(r => (r.data || '').toLowerCase().replace(/\.$/, ''));

  if (nsNames.length === 0) {
    return {
      pass: false,
      scoreModifier: -5,
      description: 'No NS records found.',
      recommendation: 'Ensure your domain has at least 2 nameservers from different providers.',
    };
  }

  if (nsNames.length === 1) {
    return {
      pass: false,
      scoreModifier: -5,
      description: 'Only 1 nameserver found. If it goes down, your domain becomes unreachable.',
      recommendation: 'Add at least one more nameserver, ideally from a different provider/network.',
    };
  }

  // Check if nameservers are on different domains (providers)
  const nsDomains = new Set();
  for (const ns of nsNames) {
    const parts = ns.split('.');
    if (parts.length >= 2) {
      nsDomains.add(parts.slice(-2).join('.'));
    }
  }

  if (nsDomains.size >= 2) {
    return {
      pass: true,
      scoreModifier: 10,
      description: `${nsNames.length} nameservers across ${nsDomains.size} providers. Good redundancy and resilience.`,
      recommendation: null,
    };
  }

  return {
    pass: true,
    scoreModifier: 5,
    description: `${nsNames.length} nameservers found, but all appear to be from the same provider.`,
    recommendation: 'Consider using nameservers from at least 2 different providers for better resilience.',
  };
}

// ── Test 4: SOA Configuration ──

function testSOA(soaResult) {
  const answers = (soaResult.Answer || []).filter(r => r.type === 6);

  if (answers.length === 0) {
    return {
      pass: false,
      scoreModifier: -5,
      description: 'No SOA record found.',
      recommendation: 'Ensure your DNS zone has a valid SOA record.',
    };
  }

  // SOA data format: primary-ns admin-email serial refresh retry expire minimum
  const soaData = answers[0].data || '';
  const parts = soaData.split(/\s+/);

  if (parts.length < 7) {
    return {
      pass: true,
      scoreModifier: 0,
      description: 'SOA record found but could not parse all fields.',
      recommendation: null,
    };
  }

  const refresh = parseInt(parts[3], 10);
  const retry = parseInt(parts[4], 10);
  const expire = parseInt(parts[5], 10);
  const minimum = parseInt(parts[6], 10);

  const issues = [];

  // RFC recommendations: refresh 1200-43200s, retry 120-7200s, expire 1209600-2419200s
  if (refresh < 1200) issues.push('refresh too low (<20 min)');
  if (refresh > 86400) issues.push('refresh too high (>24 hr)');
  if (retry < 120) issues.push('retry too low (<2 min)');
  if (expire < 604800) issues.push('expire too low (<7 days)');
  if (minimum > 86400) issues.push('negative TTL too high (>24 hr)');

  if (issues.length === 0) {
    return {
      pass: true,
      scoreModifier: 5,
      description: `SOA record is well-configured. Refresh: ${refresh}s, Retry: ${retry}s, Expire: ${expire}s.`,
      recommendation: null,
    };
  }

  return {
    pass: true,
    scoreModifier: 0,
    description: `SOA record found with minor issues: ${issues.join(', ')}.`,
    recommendation: 'Review SOA timing values. Recommended: refresh 3600, retry 900, expire 1209600, minimum 3600.',
  };
}

// ── Test 5: SPF Record ──

function testSPF(txtResult) {
  const answers = (txtResult.Answer || []).filter(r => r.type === 16);
  const txtRecords = answers.map(r => (r.data || '').replace(/^"|"$/g, ''));

  const spfRecords = txtRecords.filter(txt => txt.toLowerCase().startsWith('v=spf1'));

  if (spfRecords.length === 0) {
    return {
      pass: false,
      scoreModifier: -15,
      description: 'No SPF record found. Anyone can send email pretending to be from this domain.',
      recommendation: 'Add an SPF TXT record. Example: v=spf1 include:_spf.google.com -all',
    };
  }

  if (spfRecords.length > 1) {
    return {
      pass: false,
      scoreModifier: -10,
      description: `${spfRecords.length} SPF records found. RFC 7208 requires exactly one. Multiple records cause unpredictable behavior.`,
      recommendation: 'Merge all SPF records into a single TXT record.',
    };
  }

  const spf = spfRecords[0].toLowerCase();

  if (spf.includes('+all')) {
    return {
      pass: false,
      scoreModifier: -15,
      description: 'SPF record uses "+all" — this allows anyone to send email from this domain.',
      recommendation: 'Change "+all" to "-all" (hard fail) or "~all" (soft fail) to restrict email senders.',
    };
  }

  if (spf.includes('-all')) {
    return {
      pass: true,
      scoreModifier: 15,
      description: 'SPF record is configured with "-all" (hard fail). Unauthorized senders are rejected.',
      recommendation: null,
    };
  }

  if (spf.includes('~all')) {
    return {
      pass: true,
      scoreModifier: 10,
      description: 'SPF record is configured with "~all" (soft fail). Unauthorized senders are flagged but not always rejected.',
      recommendation: 'Consider upgrading from "~all" to "-all" for stricter enforcement once you confirm all legitimate senders are included.',
    };
  }

  if (spf.includes('?all')) {
    return {
      pass: false,
      scoreModifier: -5,
      description: 'SPF record uses "?all" (neutral). This provides no real protection against spoofing.',
      recommendation: 'Change "?all" to "-all" (hard fail) to reject unauthorized senders.',
    };
  }

  return {
    pass: true,
    scoreModifier: 5,
    description: 'SPF record is present.',
    recommendation: 'Ensure your SPF record ends with "-all" for maximum protection.',
  };
}

// ── Test 6: DMARC Record ──

function testDMARC(dmarcResult) {
  const answers = (dmarcResult.Answer || []).filter(r => r.type === 16);
  const txtRecords = answers.map(r => (r.data || '').replace(/^"|"$/g, ''));

  const dmarcRecords = txtRecords.filter(txt => txt.toLowerCase().startsWith('v=dmarc1'));

  if (dmarcRecords.length === 0) {
    return {
      pass: false,
      scoreModifier: -15,
      description: 'No DMARC record found. Email receivers cannot verify your domain\'s email authentication policy.',
      recommendation: 'Add a DMARC TXT record at _dmarc.yourdomain.com. Example: v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com',
    };
  }

  const dmarc = dmarcRecords[0].toLowerCase();
  const policyMatch = dmarc.match(/;\s*p\s*=\s*(\w+)/);
  const policy = policyMatch ? policyMatch[1] : '';

  if (policy === 'reject') {
    return {
      pass: true,
      scoreModifier: 15,
      description: 'DMARC policy is set to "reject". Fraudulent emails are blocked by receiving servers.',
      recommendation: null,
    };
  }

  if (policy === 'quarantine') {
    return {
      pass: true,
      scoreModifier: 10,
      description: 'DMARC policy is set to "quarantine". Suspicious emails are sent to spam.',
      recommendation: 'Consider upgrading to p=reject once you are confident all legitimate email passes DMARC checks.',
    };
  }

  if (policy === 'none') {
    return {
      pass: false,
      scoreModifier: -5,
      description: 'DMARC policy is set to "none" (monitoring only). Fraudulent emails are still delivered.',
      recommendation: 'Upgrade from p=none to p=quarantine or p=reject. Use "rua" reports to identify issues first.',
    };
  }

  return {
    pass: false,
    scoreModifier: -10,
    description: 'DMARC record found but policy could not be parsed.',
    recommendation: 'Ensure your DMARC record includes a valid p= tag (none, quarantine, or reject).',
  };
}

// ── Test 7: MX Records ──

function testMX(mxResult) {
  const answers = (mxResult.Answer || []).filter(r => r.type === 15);

  if (answers.length === 0) {
    // No MX is not necessarily bad — domain may not handle email
    return {
      pass: true,
      scoreModifier: 0,
      description: 'No MX records found. This domain does not appear to handle email.',
      recommendation: 'If this domain sends or receives email, add MX records pointing to your mail servers.',
    };
  }

  const mxHosts = answers.map(r => {
    const parts = (r.data || '').split(/\s+/);
    return { priority: parseInt(parts[0], 10) || 0, host: (parts[1] || '').toLowerCase().replace(/\.$/, '') };
  }).filter(mx => mx.host);

  if (mxHosts.length === 1) {
    return {
      pass: true,
      scoreModifier: 5,
      description: `1 MX record found (${mxHosts[0].host}). Consider adding a backup mail server.`,
      recommendation: 'Add a secondary MX record with a higher priority number for redundancy.',
    };
  }

  return {
    pass: true,
    scoreModifier: 10,
    description: `${mxHosts.length} MX records found. Mail delivery has redundancy.`,
    recommendation: null,
  };
}

// ── Test 8: Dangling CNAME ──

async function testDanglingCNAME(domain, cnameResult) {
  const answers = (cnameResult.Answer || []).filter(r => r.type === 5);

  if (answers.length === 0) {
    return {
      pass: true,
      scoreModifier: 10,
      description: 'No CNAME record on the apex domain. No subdomain takeover risk at this level.',
      recommendation: null,
    };
  }

  const target = (answers[0].data || '').toLowerCase().replace(/\.$/, '');

  if (!target) {
    return {
      pass: true,
      scoreModifier: 0,
      description: 'CNAME record found but target could not be parsed.',
      recommendation: null,
    };
  }

  // Try resolving the CNAME target
  const targetResult = await queryDoH(target, 'A');
  const targetAnswers = (targetResult.Answer || []).filter(r => r.type === 1);

  if (targetAnswers.length === 0 && targetResult.Status === 3) {
    // NXDOMAIN — target doesn't exist = dangling
    return {
      pass: false,
      scoreModifier: -25,
      description: `CNAME points to ${target} which does not resolve (NXDOMAIN). This is a subdomain takeover risk.`,
      recommendation: 'Remove the dangling CNAME record or point it to a valid target. An attacker could claim the target and serve content on your domain.',
    };
  }

  return {
    pass: true,
    scoreModifier: 10,
    description: `CNAME points to ${target} which resolves correctly.`,
    recommendation: null,
  };
}

// ── HMAC Token Verification (shared with scan.js) ──

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

// ── Extract raw records for display ──

function extractRawRecords(results) {
  const typeNames = { 1: 'A', 28: 'AAAA', 2: 'NS', 15: 'MX', 16: 'TXT', 257: 'CAA', 6: 'SOA', 5: 'CNAME' };
  const raw = { A: [], AAAA: [], NS: [], MX: [], TXT: [], CAA: [], SOA: [], CNAME: [] };

  for (const result of results) {
    const answers = result.Answer || [];
    for (const record of answers) {
      const typeName = typeNames[record.type];
      if (typeName && raw[typeName]) {
        raw[typeName].push({
          name: (record.name || '').replace(/\.$/, ''),
          ttl: record.TTL || 0,
          data: (record.data || '').replace(/^"|"$/g, ''),
        });
      }
    }
  }

  return raw;
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
    const key = `rl:dns:${ip}`;
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

  // ── Run all DoH queries in parallel ──
  let aResult, nsResult, soaResult, txtResult, mxResult, caaResult, dmarcResult, cnameResult, aaaaResult;

  try {
    const results = await Promise.all([
      queryDoH(domain, 'A'),
      queryDoH(domain, 'NS'),
      queryDoH(domain, 'SOA'),
      queryDoH(domain, 'TXT'),
      queryDoH(domain, 'MX'),
      queryDoH(domain, 'CAA'),
      queryDoH('_dmarc.' + domain, 'TXT'),
      queryDoH(domain, 'CNAME'),
      queryDoH(domain, 'AAAA'),
    ]);

    aResult = results[0];
    nsResult = results[1];
    soaResult = results[2];
    txtResult = results[3];
    mxResult = results[4];
    caaResult = results[5];
    dmarcResult = results[6];
    cnameResult = results[7];
    aaaaResult = results[8];
  } catch {
    return new Response(JSON.stringify({ error: 'DNS lookup failed. Please try again.' }), {
      status: 502, headers: corsHeaders,
    });
  }

  // ── Run all 8 tests ──
  const tests = {
    dnssec: testDNSSEC(aResult),
    caa: testCAA(caaResult),
    ns: testNS(nsResult),
    soa: testSOA(soaResult),
    spf: testSPF(txtResult),
    dmarc: testDMARC(dmarcResult),
    mx: testMX(mxResult),
    'dangling-cname': await testDanglingCNAME(domain, cnameResult),
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

  // ── Raw records for display ──
  const rawRecords = extractRawRecords([aResult, aaaaResult, nsResult, mxResult, txtResult, caaResult, soaResult, cnameResult]);

  // ── Response ──
  const result = {
    domain,
    grade,
    score,
    scannedAt: new Date().toISOString(),
    tests,
    rawRecords,
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
