/**
 * Security Headers Checker API — Observatory v5 Algorithm
 * Cloudflare Pages Function — POST /api/scan
 *
 * Implements MDN HTTP Observatory v5 scoring with 11 scored tests,
 * 13-grade scale, and extra-credit gating.
 */

// ── SSRF Prevention ──

const BLOCKED_IP_PATTERNS = [
  /^127\./,
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^169\.254\./,
  /^0\./,
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,
  /^198\.1[89]\./,
  /^::1$/,
  /^fc00:/i,
  /^fd00:/i,
  /^fe80:/i,
  /^ff00:/i,
  /^::$/,
];

const BLOCKED_HOSTNAMES = [
  'localhost',
  'localhost.localdomain',
  '0.0.0.0',
  '[::1]',
  'metadata.google.internal',
  'metadata.google',
  '169.254.169.254',
];

// ── SSRF: DNS Rebinding Protection ──

const DOH_ENDPOINT = 'https://cloudflare-dns.com/dns-query';
const DOH_TIMEOUT_MS = 3000;

async function queryDoH(name, type) {
  const url = `${DOH_ENDPOINT}?name=${encodeURIComponent(name)}&type=${type}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DOH_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      headers: { 'Accept': 'application/dns-json' },
      signal: controller.signal,
    });
    if (!res.ok) return { Status: -1, Answer: [] };
    return await res.json();
  } catch {
    return { Status: -1, Answer: [] };
  } finally {
    clearTimeout(timer);
  }
}

function isPrivateIP(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(p => isNaN(p))) return false;
  if (parts[0] === 10) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  if (parts[0] === 127) return true;
  if (parts[0] === 169 && parts[1] === 254) return true;
  if (parts[0] === 0) return true;
  return false;
}

async function resolvesDangerousIP(hostname) {
  const result = await queryDoH(hostname, 'A');
  const answers = (result.Answer || []).filter(r => r.type === 1);
  for (const record of answers) {
    const ip = (record.data || '').trim();
    if (isPrivateIP(ip)) return true;
  }
  return false;
}

// ── Constants ──

function getAllowedOrigins(env) {
  if (env && env.ALLOWED_ORIGINS) {
    return env.ALLOWED_ORIGINS.split(',').map(o => o.trim());
  }
  return ['*'];
}

const MAX_REDIRECTS = 10;
const FETCH_TIMEOUT_MS = 8000;
const SECONDARY_TIMEOUT_MS = 3000;
const MAX_BODY_SIZE = 512 * 1024; // 512 KB for SRI check
const USER_AGENT = 'AppSecSanta-HeadersChecker/2.0 (+https://appsecsanta.com)';

// Session cookie name patterns (case-insensitive matching)
const SESSION_COOKIE_PATTERNS = [
  'aspsessionid', 'asp.net_sessionid', 'cfid', 'cftoken',
  'jsessionid', 'phpsessid', 'sess', 'sid',
  '__secure-', '__host-',
];

// CSRF cookie name patterns (case-insensitive matching)
const CSRF_COOKIE_PATTERNS = [
  'csrf', 'xsrf', '_token', 'antiforgery', 'csrftoken', 'xsrftoken',
];

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

// ── URL Validation ──

function validateUrl(input) {
  if (!input || typeof input !== 'string') {
    return { valid: false, error: 'URL is required.' };
  }

  let raw = input.trim();
  if (!/^https?:\/\//i.test(raw)) {
    raw = 'https://' + raw;
  }

  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    return { valid: false, error: 'Invalid URL format.' };
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return { valid: false, error: 'Only HTTP and HTTPS URLs are allowed.' };
  }

  if (parsed.username || parsed.password) {
    return { valid: false, error: 'URLs with credentials are not allowed.' };
  }

  if (!parsed.hostname.includes('.')) {
    return { valid: false, error: 'Invalid hostname.' };
  }

  const host = parsed.hostname.toLowerCase();
  if (BLOCKED_HOSTNAMES.includes(host)) {
    return { valid: false, error: 'Scanning private or reserved addresses is not allowed.' };
  }

  for (const pattern of BLOCKED_IP_PATTERNS) {
    if (pattern.test(host)) {
      return { valid: false, error: 'Scanning private or reserved addresses is not allowed.' };
    }
  }

  return { valid: true, url: parsed.toString() };
}

// ── Fetch Helpers ──

/**
 * Follow redirect chain manually, returning final response + chain info.
 * Uses GET with manual redirect tracking. Validates each hop for SSRF.
 */
async function followRedirects(startUrl, options = {}) {
  const {
    timeout = FETCH_TIMEOUT_MS,
    captureBody = false,
    extraHeaders = {},
  } = options;

  let currentUrl = startUrl;
  let redirectCount = 0;
  let response;
  const chain = []; // { url, status }

  while (redirectCount <= MAX_REDIRECTS) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    try {
      response = await fetch(currentUrl, {
        method: 'GET',
        headers: { 'User-Agent': USER_AGENT, ...extraHeaders },
        redirect: 'manual',
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }

    if ([301, 302, 303, 307, 308].includes(response.status)) {
      chain.push({ url: currentUrl, status: response.status });
      const location = response.headers.get('location');
      if (!location) break;

      let nextUrl;
      try {
        nextUrl = new URL(location, currentUrl).toString();
      } catch {
        break;
      }

      const check = validateUrl(nextUrl);
      if (!check.valid) {
        throw new Error('Redirect target is not allowed.');
      }

      currentUrl = check.url;
      redirectCount++;
      continue;
    }

    break;
  }

  chain.push({ url: currentUrl, status: response.status });

  let body = null;
  if (captureBody) {
    try {
      const reader = response.body.getReader();
      const chunks = [];
      let totalSize = 0;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        totalSize += value.length;
        if (totalSize <= MAX_BODY_SIZE) {
          chunks.push(value);
        } else {
          reader.cancel();
          break;
        }
      }
      const merged = new Uint8Array(Math.min(totalSize, MAX_BODY_SIZE));
      let offset = 0;
      for (const chunk of chunks) {
        const toCopy = Math.min(chunk.length, MAX_BODY_SIZE - offset);
        merged.set(chunk.subarray(0, toCopy), offset);
        offset += toCopy;
      }
      body = new TextDecoder().decode(merged);
    } catch {
      // Body capture failed — non-fatal
    }
  }

  return { response, finalUrl: currentUrl, chain, body };
}

// ── Collect Set-Cookie headers ──

function collectSetCookieHeaders(headers) {
  const cookies = [];
  headers.forEach((value, name) => {
    if (name.toLowerCase() === 'set-cookie') {
      cookies.push(value);
    }
  });
  return cookies;
}

// ── Meta Tag Extraction ──

function extractMetaTag(htmlBody, nameOrHttpEquiv) {
  if (!htmlBody) return null;
  // Match <meta http-equiv="..." content="..."> or <meta name="..." content="...">
  const lower = nameOrHttpEquiv.toLowerCase();
  const patterns = [
    new RegExp(`<meta\\s+http-equiv=["']${lower}["']\\s+content=["']([^"']+)["']`, 'i'),
    new RegExp(`<meta\\s+content=["']([^"']+)["']\\s+http-equiv=["']${lower}["']`, 'i'),
    new RegExp(`<meta\\s+name=["']${lower}["']\\s+content=["']([^"']+)["']`, 'i'),
    new RegExp(`<meta\\s+content=["']([^"']+)["']\\s+name=["']${lower}["']`, 'i'),
  ];
  for (const pattern of patterns) {
    const match = htmlBody.match(pattern);
    if (match) return match[1];
  }
  return null;
}

// ── CSP Parser ──

function parseCSPDirectives(policyStr) {
  const directives = {};
  for (const part of policyStr.split(';')) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const tokens = trimmed.split(/\s+/);
    const name = tokens[0].toLowerCase();
    directives[name] = tokens.slice(1).map(v => v.toLowerCase());
  }
  return directives;
}

/**
 * Get the effective source list for a directive, falling back to default-src.
 */
function getEffectiveSources(directives, directive) {
  if (directives[directive]) return directives[directive];
  if (directive !== 'default-src' && directives['default-src']) return directives['default-src'];
  return null;
}

// ── Test 1: Content-Security-Policy ──

function testCSP(headers, htmlBody) {
  let cspHeader = headers.get('content-security-policy');
  let cspSource = 'header';

  // If no CSP header, check for meta tag
  if (!cspHeader && htmlBody) {
    const metaCSP = extractMetaTag(htmlBody, 'Content-Security-Policy');
    if (metaCSP) {
      cspHeader = metaCSP;
      cspSource = 'meta';
    }
  }

  if (!cspHeader) {
    // Check for report-only mode
    const reportOnly = headers.get('content-security-policy-report-only');
    if (reportOnly) {
      return {
        result: 'csp-not-implemented-but-reporting-enabled',
        scoreModifier: -25,
        pass: false,
        description: 'CSP is in report-only mode (monitoring). It does not enforce any restrictions yet.',
        recommendation: 'Switch from Content-Security-Policy-Report-Only to Content-Security-Policy to enforce your policy.',
        data: { reportOnly: true, policy: reportOnly },
      };
    }

    return {
      result: 'csp-not-implemented',
      scoreModifier: -25,
      pass: false,
      description: 'Content-Security-Policy header is not set. This is the most important security header — it prevents XSS, data injection, and clickjacking.',
      recommendation: "Add a Content-Security-Policy header. Start with: Content-Security-Policy: default-src 'self'",
      data: {},
    };
  }

  // Multiple CSP headers are intersected; analyze the first for scoring
  const policies = cspHeader.split(/,(?![^(]*\))/).map(p => p.trim()).filter(Boolean);
  const directives = parseCSPDirectives(policies[0]);
  const data = { policy: policies[0], directives, source: cspSource };

  // Check for insecure scheme sources in passive content directives
  const passiveDirectives = ['img-src', 'media-src', 'font-src'];
  let hasInsecureSchemePassive = false;
  for (const dir of passiveDirectives) {
    const sources = getEffectiveSources(directives, dir);
    if (sources && (sources.includes('http:') || sources.includes('ftp:'))) {
      hasInsecureSchemePassive = true;
    }
  }

  // Check for insecure scheme in active content
  const activeDirectives = ['script-src', 'style-src', 'default-src', 'object-src'];
  let hasInsecureSchemeActive = false;
  for (const dir of activeDirectives) {
    const sources = getEffectiveSources(directives, dir);
    if (sources && (sources.includes('http:') || sources.includes('ftp:'))) {
      hasInsecureSchemeActive = true;
    }
  }

  const scriptSources = getEffectiveSources(directives, 'script-src') || [];
  const styleSources = getEffectiveSources(directives, 'style-src') || [];
  const defaultSources = directives['default-src'] || [];

  const hasUnsafeInline = (sources) => sources.includes("'unsafe-inline'");
  const hasUnsafeEval = (sources) => sources.includes("'unsafe-eval'");
  const hasNonceOrHash = (sources) =>
    sources.some(s => /^'nonce-/.test(s) || /^'sha(256|384|512)-/.test(s));
  const hasStrictDynamic = (sources) => sources.includes("'strict-dynamic'");
  const hasWildcard = (sources) => sources.includes('*');

  // unsafe-inline is overridden by nonce/hash/strict-dynamic
  const scriptUnsafeInline = hasUnsafeInline(scriptSources) &&
    !hasNonceOrHash(scriptSources) && !hasStrictDynamic(scriptSources);
  const scriptUnsafeEval = hasUnsafeEval(scriptSources);
  const styleUnsafeInline = hasUnsafeInline(styleSources) &&
    !hasNonceOrHash(styleSources) && !hasStrictDynamic(styleSources);
  const defaultUnsafeInline = hasUnsafeInline(defaultSources) &&
    !hasNonceOrHash(defaultSources) && !hasStrictDynamic(defaultSources);
  const defaultUnsafeEval = hasUnsafeEval(defaultSources);

  const hasWildcardScript = hasWildcard(scriptSources) || hasWildcard(defaultSources);
  const defaultSrcNone = defaultSources.length === 1 && defaultSources[0] === "'none'";

  let result, scoreModifier;

  if (hasWildcardScript || hasInsecureSchemeActive) {
    result = 'csp-implemented-with-insecure-scheme';
    scoreModifier = -20;
  } else if (scriptUnsafeInline || defaultUnsafeInline) {
    result = 'csp-implemented-with-unsafe-inline';
    scoreModifier = -20;
  } else if (scriptUnsafeEval || defaultUnsafeEval) {
    result = 'csp-implemented-with-unsafe-eval';
    scoreModifier = -10;
  } else if (hasInsecureSchemePassive) {
    result = 'csp-implemented-with-insecure-scheme-in-passive-content';
    scoreModifier = -10;
  } else if (styleUnsafeInline) {
    result = 'csp-implemented-with-unsafe-inline-in-style-src-only';
    scoreModifier = 0;
  } else if (defaultSrcNone) {
    result = 'csp-implemented-with-no-unsafe-default-src-none';
    scoreModifier = 10;
  } else {
    result = 'csp-implemented-with-no-unsafe';
    scoreModifier = 5;
  }

  // Extract frame-ancestors for XFO test
  const frameAncestors = directives['frame-ancestors'] || null;
  data.frameAncestors = frameAncestors;

  const pass = scoreModifier >= 0;

  const descriptions = {
    'csp-implemented-with-no-unsafe-default-src-none': "CSP is implemented with no unsafe directives and default-src 'none'. Excellent configuration.",
    'csp-implemented-with-no-unsafe': 'CSP is implemented with no unsafe directives. Strong protection against XSS.',
    'csp-implemented-with-unsafe-inline-in-style-src-only': "CSP is implemented but uses 'unsafe-inline' in style-src. This is a common and generally acceptable pattern.",
    'csp-implemented-with-unsafe-eval': "CSP is implemented but uses 'unsafe-eval', which allows dynamic code execution via eval().",
    'csp-implemented-with-unsafe-inline': "CSP is implemented but uses 'unsafe-inline' without nonce/hash, significantly weakening XSS protection.",
    'csp-implemented-with-insecure-scheme-in-passive-content': 'CSP allows insecure schemes (http:/ftp:) in passive content directives (img-src, media-src).',
    'csp-implemented-with-insecure-scheme': 'CSP allows insecure schemes or wildcards in active content directives, providing minimal protection.',
  };

  const recommendations = {
    'csp-implemented-with-unsafe-eval': "Remove 'unsafe-eval' and refactor code to avoid eval(), Function(), and similar dynamic execution.",
    'csp-implemented-with-unsafe-inline': "Replace 'unsafe-inline' with nonce-based or hash-based CSP. Use 'strict-dynamic' for modern browsers.",
    'csp-implemented-with-insecure-scheme-in-passive-content': 'Remove http: and ftp: scheme sources. Use https: or specific origins instead.',
    'csp-implemented-with-insecure-scheme': "Remove wildcard (*) and insecure scheme sources from active content directives. Set a restrictive default-src like 'self' or 'none'.",
  };

  return {
    result,
    scoreModifier,
    pass,
    description: descriptions[result] || `CSP is configured (${result}).`,
    recommendation: recommendations[result] || null,
    data,
  };
}

// ── Test 2: Cookies ──

function isSessionCookie(name) {
  const lower = name.toLowerCase();
  return SESSION_COOKIE_PATTERNS.some(pattern => lower.includes(pattern));
}

function isCsrfCookie(name) {
  const lower = name.toLowerCase();
  return CSRF_COOKIE_PATTERNS.some(pattern => lower.includes(pattern));
}

function parseCookieName(setCookieStr) {
  const eqIdx = setCookieStr.indexOf('=');
  if (eqIdx === -1) return setCookieStr.split(';')[0].trim();
  return setCookieStr.substring(0, eqIdx).trim();
}

function testCookies(setCookieHeaders, hstsEnabled) {
  if (!setCookieHeaders || setCookieHeaders.length === 0) {
    return {
      result: 'cookies-not-found',
      scoreModifier: 0,
      pass: true,
      description: 'No cookies detected. Cookie security analysis is not applicable.',
      recommendation: null,
      data: { cookies: [] },
    };
  }

  const cookieData = [];
  let hasSessionCookies = false;
  let allSessionSecure = true;
  let allSessionHttpOnly = true;
  let allSessionSameSite = true;
  let sessionCount = 0;
  let hasCsrfCookies = false;
  let csrfWithoutSameSite = false;
  let hasInvalidSameSite = false;

  for (const raw of setCookieHeaders) {
    const name = parseCookieName(raw);
    const lower = raw.toLowerCase();
    const isSession = isSessionCookie(name);
    const isCsrf = isCsrfCookie(name);
    const secure = /;\s*secure/i.test(lower);
    const httpOnly = /;\s*httponly/i.test(lower);
    const sameSiteMatch = lower.match(/;\s*samesite=(\S+)/i);
    const sameSiteRaw = sameSiteMatch ? sameSiteMatch[1] : null;
    const sameSiteValid = sameSiteRaw && /^(strict|lax|none)$/i.test(sameSiteRaw);
    const sameSite = sameSiteValid;
    const sameSiteValue = sameSiteValid ? sameSiteRaw.toLowerCase() : null;
    const path = /;\s*path=\//i.test(lower);
    const hasPrefix = name.startsWith('__Secure-') || name.startsWith('__Host-');

    // Detect invalid SameSite values
    if (sameSiteRaw && !sameSiteValid) {
      hasInvalidSameSite = true;
    }

    cookieData.push({ name, isSession, isCsrf, secure, httpOnly, sameSite, sameSiteValue, path, hasPrefix });

    if (isSession) {
      hasSessionCookies = true;
      sessionCount++;
      if (!secure) allSessionSecure = false;
      if (!httpOnly) allSessionHttpOnly = false;
      if (!sameSite) allSessionSameSite = false;
    }

    if (isCsrf) {
      hasCsrfCookies = true;
      if (!sameSiteValue || sameSiteValue === 'none') {
        csrfWithoutSameSite = true;
      }
    }
  }

  if (!hasSessionCookies) {
    // Still check for CSRF and invalid SameSite issues even without session cookies
    if (hasInvalidSameSite) {
      return {
        result: 'cookies-invalid-samesite',
        scoreModifier: -20,
        pass: false,
        description: 'One or more cookies have an invalid SameSite attribute value. Browsers may ignore the attribute entirely.',
        recommendation: 'Set SameSite to one of: Strict, Lax, or None. Any other value is ignored by browsers.',
        data: { cookies: cookieData },
      };
    }
    return {
      result: 'cookies-not-found',
      scoreModifier: 0,
      pass: true,
      description: 'Cookies are set but none appear to be session cookies. No session cookie security issues detected.',
      recommendation: null,
      data: { cookies: cookieData },
    };
  }

  // Check most severe issues first, return the worst result
  let result, scoreModifier;

  if (!allSessionSecure && !hstsEnabled) {
    result = 'cookies-without-secure-flag';
    scoreModifier = -40;
  } else if (!allSessionHttpOnly) {
    result = 'cookies-without-httponly-flag';
    scoreModifier = -30;
  } else if (!allSessionSecure && hstsEnabled) {
    result = 'cookies-session-without-secure-flag-but-protected-by-hsts';
    scoreModifier = -20;
  } else if (hasInvalidSameSite) {
    result = 'cookies-invalid-samesite';
    scoreModifier = -20;
  } else if (csrfWithoutSameSite) {
    result = 'cookies-without-samesite-on-csrf';
    scoreModifier = -20;
  } else if (allSessionSameSite) {
    result = 'cookies-secure-with-httponly-sessions-and-samesite';
    scoreModifier = 5;
  } else {
    result = 'cookies-secure-with-httponly-sessions';
    scoreModifier = 0;
  }

  const pass = scoreModifier >= 0;

  const descriptions = {
    'cookies-secure-with-httponly-sessions-and-samesite': 'Session cookies use Secure, HttpOnly, and SameSite attributes. Excellent cookie security.',
    'cookies-secure-with-httponly-sessions': 'Session cookies use Secure and HttpOnly flags. Consider adding SameSite for additional CSRF protection.',
    'cookies-without-httponly-flag': 'Session cookies are missing the HttpOnly flag. JavaScript can access session tokens, increasing XSS impact.',
    'cookies-session-without-secure-flag-but-protected-by-hsts': 'Session cookies are missing the Secure flag but HSTS provides partial protection against transmission over HTTP.',
    'cookies-without-secure-flag': 'Session cookies are missing the Secure flag. Cookies may be transmitted over unencrypted HTTP connections.',
    'cookies-without-samesite-on-csrf': 'Anti-CSRF cookies are missing the SameSite attribute (or set to None). Without SameSite=Strict or SameSite=Lax, CSRF tokens may be sent with cross-origin requests.',
    'cookies-invalid-samesite': 'One or more cookies have an invalid SameSite attribute value. Browsers may ignore the attribute entirely.',
  };

  const recommendations = {
    'cookies-secure-with-httponly-sessions': 'Add SameSite=Lax or SameSite=Strict to session cookies for CSRF protection.',
    'cookies-without-httponly-flag': 'Add HttpOnly flag to session cookies to prevent JavaScript access.',
    'cookies-session-without-secure-flag-but-protected-by-hsts': 'Add the Secure flag to all session cookies.',
    'cookies-without-secure-flag': 'Add the Secure flag to all session cookies to prevent transmission over HTTP.',
    'cookies-without-samesite-on-csrf': 'Add SameSite=Lax or SameSite=Strict to anti-CSRF cookies to prevent them from being sent in cross-origin requests.',
    'cookies-invalid-samesite': 'Set SameSite to one of: Strict, Lax, or None. Any other value is ignored by browsers.',
  };

  return {
    result,
    scoreModifier,
    pass,
    description: descriptions[result] || `Session cookie security: ${result}.`,
    recommendation: recommendations[result] || null,
    data: { cookies: cookieData, sessionCount },
  };
}

// ── Test 3: CORS ──

function testCORS(corsResponse) {
  if (!corsResponse) {
    return {
      result: 'cors-test-failed',
      scoreModifier: 0,
      pass: true,
      description: 'CORS test could not be completed. Scoring is neutral.',
      recommendation: null,
      data: {},
    };
  }

  const acao = corsResponse.headers.get('access-control-allow-origin');
  const acac = corsResponse.headers.get('access-control-allow-credentials');

  if (!acao) {
    return {
      result: 'cors-not-implemented',
      scoreModifier: 0,
      pass: true,
      description: 'No CORS headers detected. The server does not allow cross-origin requests.',
      recommendation: null,
      data: { acao: null, acac: null },
    };
  }

  const reflectsOrigin = acao === 'https://evil.example.com';
  const allowsCredentials = acac && acac.toLowerCase() === 'true';
  const isWildcard = acao === '*';

  if (reflectsOrigin && allowsCredentials) {
    return {
      result: 'cors-allows-origin-with-credentials',
      scoreModifier: -50,
      pass: false,
      description: 'CORS is misconfigured: reflects any origin AND allows credentials. This enables cross-site data theft.',
      recommendation: 'Do not reflect arbitrary origins with Access-Control-Allow-Credentials: true. Whitelist specific trusted origins.',
      data: { acao, acac, reflectsOrigin, allowsCredentials },
    };
  }

  if (reflectsOrigin) {
    return {
      result: 'cors-allows-any-origin',
      scoreModifier: -25,
      pass: false,
      description: 'CORS reflects any origin without credential access. Resources can be read cross-origin.',
      recommendation: 'Restrict Access-Control-Allow-Origin to specific trusted origins instead of reflecting the request origin.',
      data: { acao, acac, reflectsOrigin, allowsCredentials },
    };
  }

  if (isWildcard) {
    return {
      result: 'cors-allows-wildcard',
      scoreModifier: 0,
      pass: true,
      description: 'CORS uses wildcard (*) origin. Public resources are accessible cross-origin, but credentials are blocked by browsers.',
      recommendation: 'If the resource is not intended to be public, restrict Access-Control-Allow-Origin to specific origins.',
      data: { acao, acac, reflectsOrigin: false, allowsCredentials },
    };
  }

  return {
    result: 'cors-restricted',
    scoreModifier: 0,
    pass: true,
    description: `CORS is configured with a specific origin (${acao}). Cross-origin access is restricted.`,
    recommendation: null,
    data: { acao, acac, reflectsOrigin: false, allowsCredentials },
  };
}

// ── Test 4: Redirection (HTTP → HTTPS) ──

function testRedirection(httpsChain, httpResult) {
  const initialUrl = httpsChain[0]?.url || '';

  if (!httpResult) {
    if (initialUrl.startsWith('https://')) {
      return {
        result: 'redirection-not-needed-on-https',
        scoreModifier: 0,
        pass: true,
        description: 'Site was accessed via HTTPS. HTTP redirect test could not be completed.',
        recommendation: 'Ensure HTTP requests redirect to HTTPS.',
        data: { httpsChain },
      };
    }
    return {
      result: 'redirection-off',
      scoreModifier: -20,
      pass: false,
      description: 'Could not verify HTTP to HTTPS redirection.',
      recommendation: 'Redirect all HTTP requests to HTTPS with a 301 redirect.',
      data: { httpsChain },
    };
  }

  const httpChain = httpResult.chain || [];
  const httpFinalUrl = httpResult.finalUrl || '';
  const httpRedirectsToHttps = httpFinalUrl.startsWith('https://');
  const firstRedirect = httpChain.length > 1 ? httpChain[0] : null;
  const uses301 = firstRedirect && firstRedirect.status === 301;

  let redirectsToSameHost = false;
  try {
    const httpHost = new URL(httpChain[0]?.url || '').hostname;
    const httpsHost = new URL(httpFinalUrl).hostname;
    redirectsToSameHost = httpHost === httpsHost ||
      httpsHost === 'www.' + httpHost ||
      httpHost === 'www.' + httpsHost;
  } catch { /* ignore */ }

  if (httpRedirectsToHttps && uses301 && redirectsToSameHost) {
    return {
      result: 'redirection-all-redirects-preloaded',
      scoreModifier: 0,
      pass: true,
      description: 'HTTP redirects to HTTPS with a 301 status code. Proper redirect configuration.',
      recommendation: null,
      data: { httpChain, httpsChain, httpFinalUrl },
    };
  }

  if (httpRedirectsToHttps && redirectsToSameHost) {
    return {
      result: 'redirection-to-https',
      scoreModifier: 0,
      pass: true,
      description: `HTTP redirects to HTTPS (using ${firstRedirect?.status || 'redirect'} status). Consider using 301 for permanent redirects.`,
      recommendation: uses301 ? null : 'Use a 301 (permanent) redirect from HTTP to HTTPS for better SEO and caching.',
      data: { httpChain, httpsChain, httpFinalUrl },
    };
  }

  if (httpRedirectsToHttps && !redirectsToSameHost) {
    return {
      result: 'redirection-to-https-different-host',
      scoreModifier: -5,
      pass: false,
      description: 'HTTP redirects to HTTPS but on a different host. The original domain does not enforce HTTPS.',
      recommendation: 'Redirect HTTP to HTTPS on the same host before any cross-domain redirects.',
      data: { httpChain, httpsChain, httpFinalUrl },
    };
  }

  return {
    result: 'redirection-missing',
    scoreModifier: -20,
    pass: false,
    description: 'HTTP does not redirect to HTTPS. Users accessing the site via HTTP are not protected.',
    recommendation: 'Add a 301 redirect from HTTP to HTTPS: http://example.com → https://example.com',
    data: { httpChain, httpsChain, httpFinalUrl },
  };
}

// ── Test 5: Referrer-Policy ──

function testReferrerPolicy(headers, htmlBody) {
  let value = headers.get('referrer-policy');

  // If no header, check for meta tag
  if (!value && htmlBody) {
    const metaReferrer = extractMetaTag(htmlBody, 'referrer');
    if (metaReferrer) {
      value = metaReferrer;
    }
  }

  if (!value) {
    return {
      result: 'referrer-policy-not-implemented',
      scoreModifier: 0,
      pass: true,
      description: 'Referrer-Policy is not explicitly set. Browsers default to strict-origin-when-cross-origin, which provides reasonable protection.',
      recommendation: 'Consider explicitly setting Referrer-Policy: strict-origin-when-cross-origin to ensure consistent behavior across all browsers.',
      data: {},
    };
  }

  // Can contain multiple comma-separated values; browser uses the last valid one
  const policies = value.split(',').map(p => p.trim().toLowerCase()).filter(Boolean);
  const effectivePolicy = policies[policies.length - 1];

  const secure = ['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin'];
  const acceptable = ['no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin'];

  if (secure.includes(effectivePolicy)) {
    return {
      result: 'referrer-policy-secure',
      scoreModifier: 5,
      pass: true,
      description: `Referrer-Policy is set to "${effectivePolicy}" — referrer leakage is well-controlled.`,
      recommendation: null,
      data: { policy: effectivePolicy },
    };
  }

  if (acceptable.includes(effectivePolicy)) {
    return {
      result: 'referrer-policy-partial',
      scoreModifier: 0,
      pass: true,
      description: `Referrer-Policy is set to "${effectivePolicy}". This provides some protection but could be stricter.`,
      recommendation: "Consider using 'strict-origin-when-cross-origin' or 'no-referrer' for stronger privacy.",
      data: { policy: effectivePolicy },
    };
  }

  if (effectivePolicy === 'unsafe-url') {
    return {
      result: 'referrer-policy-unsafe',
      scoreModifier: -5,
      pass: false,
      description: 'Referrer-Policy is set to "unsafe-url" — the full URL is leaked to all origins.',
      recommendation: "Change to 'strict-origin-when-cross-origin' or 'no-referrer'.",
      data: { policy: effectivePolicy },
    };
  }

  return {
    result: 'referrer-policy-unknown',
    scoreModifier: 0,
    pass: true,
    description: `Referrer-Policy is set to "${effectivePolicy}".`,
    recommendation: null,
    data: { policy: effectivePolicy },
  };
}

// ── Test 6: HSTS ──

function testHSTS(headers) {
  const value = headers.get('strict-transport-security');

  if (!value) {
    return {
      result: 'hsts-not-implemented',
      scoreModifier: -20,
      pass: false,
      description: 'Strict-Transport-Security is not set. Users can be downgraded from HTTPS to HTTP via man-in-the-middle attacks.',
      recommendation: 'Add the header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
      data: {},
    };
  }

  const maxAgeMatch = value.match(/max-age=(\d+)/i);
  const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
  const hasIncludeSubDomains = /includeSubDomains/i.test(value);
  const hasPreload = /preload/i.test(value);

  const SIX_MONTHS = 15768000;
  const ONE_YEAR = 31536000;

  if (maxAge < SIX_MONTHS) {
    return {
      result: 'hsts-implemented-max-age-less-than-six-months',
      scoreModifier: -10,
      pass: false,
      description: `HSTS is set but max-age is ${maxAge} seconds (${Math.round(maxAge / 86400)} days). Minimum recommended is 6 months (15768000 seconds).`,
      recommendation: 'Increase max-age to at least 15768000 (6 months), ideally 31536000 (1 year).',
      data: { maxAge, hasIncludeSubDomains, hasPreload },
    };
  }

  const preloadEligible = maxAge >= ONE_YEAR && hasIncludeSubDomains && hasPreload;

  if (preloadEligible) {
    return {
      result: 'hsts-preloaded',
      scoreModifier: 5,
      pass: true,
      description: `HSTS is configured for preloading: max-age=${maxAge}, includeSubDomains, preload. Excellent configuration.`,
      recommendation: null,
      data: { maxAge, hasIncludeSubDomains, hasPreload, preloadEligible },
    };
  }

  return {
    result: 'hsts-implemented',
    scoreModifier: 0,
    pass: true,
    description: `HSTS is set with max-age=${maxAge} seconds (${Math.round(maxAge / 86400)} days).${hasIncludeSubDomains ? ' includeSubDomains is set.' : ''}${hasPreload ? ' preload is set.' : ''}`,
    recommendation: 'For HSTS preloading, set max-age to at least 31536000 and add includeSubDomains and preload directives.',
    data: { maxAge, hasIncludeSubDomains, hasPreload, preloadEligible },
  };
}

// ── Test 7: Subresource Integrity (SRI) ──

function testSRI(htmlBody) {
  if (!htmlBody) {
    return {
      result: 'sri-not-checked',
      scoreModifier: 0,
      pass: true,
      description: 'Could not retrieve page body for SRI analysis. Scoring is neutral.',
      recommendation: null,
      data: {},
    };
  }

  // Strip HTML comments to avoid false matches
  const cleaned = htmlBody.replace(/<!--[\s\S]*?-->/g, '');

  // Find all <script src="..."> tags (external scripts)
  const scriptTagRegex = /<script\b[^>]*\bsrc\s*=\s*["'][^"']+["'][^>]*>/gi;
  const scripts = cleaned.match(scriptTagRegex) || [];

  if (scripts.length === 0) {
    return {
      result: 'sri-not-needed',
      scoreModifier: 0,
      pass: true,
      description: 'No external scripts found on the page. SRI is not applicable.',
      recommendation: null,
      data: { externalScripts: 0 },
    };
  }

  let withIntegrity = 0;
  let withoutIntegrity = 0;
  const missingIntegrity = [];

  for (const tag of scripts) {
    const srcMatch = tag.match(/\bsrc\s*=\s*["']([^"']+)["']/i);
    const src = srcMatch ? srcMatch[1] : '';

    // Skip same-origin scripts (relative URLs)
    const isExternal = /^(https?:)?\/\//i.test(src);
    if (!isExternal) continue;

    const hasIntegrity = /\bintegrity\s*=\s*["']/i.test(tag);
    if (hasIntegrity) {
      withIntegrity++;
    } else {
      withoutIntegrity++;
      missingIntegrity.push(src);
    }
  }

  const totalExternal = withIntegrity + withoutIntegrity;

  if (totalExternal === 0) {
    return {
      result: 'sri-not-needed',
      scoreModifier: 0,
      pass: true,
      description: 'No third-party scripts found on the page. SRI is not applicable.',
      recommendation: null,
      data: { externalScripts: 0 },
    };
  }

  if (withoutIntegrity === 0) {
    return {
      result: 'sri-implemented',
      scoreModifier: 5,
      pass: true,
      description: `All ${totalExternal} external script(s) use Subresource Integrity. Third-party script tampering is mitigated.`,
      recommendation: null,
      data: { totalExternal, withIntegrity, withoutIntegrity },
    };
  }

  // Check if all external scripts without integrity are loaded securely (HTTPS)
  var allSecure = missingIntegrity.every(function (src) {
    return /^https:/i.test(src) || /^\/\//i.test(src);
  });

  if (withIntegrity > 0) {
    return {
      result: 'sri-partially-implemented',
      scoreModifier: allSecure ? -5 : -25,
      pass: false,
      description: `${withoutIntegrity} of ${totalExternal} external scripts are missing SRI integrity attributes.`,
      recommendation: 'Add integrity and crossorigin attributes to all external scripts. Generate hashes using srihash.org.',
      data: { totalExternal, withIntegrity, withoutIntegrity, missingIntegrity: missingIntegrity.slice(0, 5) },
    };
  }

  if (allSecure) {
    return {
      result: 'sri-not-implemented-but-external-scripts-loaded-securely',
      scoreModifier: -5,
      pass: false,
      description: `External scripts are loaded over HTTPS but without Subresource Integrity. SRI would provide additional protection against CDN compromises.`,
      recommendation: 'Add integrity and crossorigin attributes to external <script> tags for defense-in-depth.',
      data: { totalExternal, withIntegrity, withoutIntegrity, missingIntegrity: missingIntegrity.slice(0, 5) },
    };
  }

  return {
    result: 'sri-not-implemented-and-external-scripts-not-loaded-securely',
    scoreModifier: -50,
    pass: false,
    description: `External scripts are loaded without Subresource Integrity and some use insecure protocols. Third-party scripts could be tampered with.`,
    recommendation: 'Load all external scripts over HTTPS and add integrity and crossorigin attributes.',
    data: { totalExternal, withIntegrity, withoutIntegrity, missingIntegrity: missingIntegrity.slice(0, 5) },
  };
}

// ── Test 8: X-Content-Type-Options ──

function testXContentTypeOptions(headers) {
  const value = headers.get('x-content-type-options');

  if (!value) {
    return {
      result: 'x-content-type-options-not-implemented',
      scoreModifier: -5,
      pass: false,
      description: 'X-Content-Type-Options is not set. Browsers may MIME-sniff responses, potentially executing uploaded files as scripts.',
      recommendation: 'Add the header: X-Content-Type-Options: nosniff',
      data: {},
    };
  }

  if (value.toLowerCase().trim() === 'nosniff') {
    return {
      result: 'x-content-type-options-nosniff',
      scoreModifier: 0,
      pass: true,
      description: 'X-Content-Type-Options is set to "nosniff", preventing MIME-type sniffing.',
      recommendation: null,
      data: { value },
    };
  }

  return {
    result: 'x-content-type-options-invalid',
    scoreModifier: -5,
    pass: false,
    description: `X-Content-Type-Options is set to "${value}" — expected "nosniff".`,
    recommendation: 'Set the value to "nosniff".',
    data: { value },
  };
}

// ── Test 9: X-Frame-Options ──

function testXFrameOptions(headers, cspData) {
  const value = headers.get('x-frame-options');
  const frameAncestors = cspData?.data?.frameAncestors;

  // CSP frame-ancestors supersedes X-Frame-Options
  if (frameAncestors) {
    const hasNoneOrSelf = frameAncestors.includes("'none'") || frameAncestors.includes("'self'");
    if (hasNoneOrSelf) {
      return {
        result: 'x-frame-options-implemented-via-csp',
        scoreModifier: 5,
        pass: true,
        description: `Framing is controlled via CSP frame-ancestors (${frameAncestors.join(' ')}). This supersedes X-Frame-Options.`,
        recommendation: null,
        data: { xfo: value, frameAncestors },
      };
    }
  }

  if (!value) {
    return {
      result: 'x-frame-options-not-implemented',
      scoreModifier: -20,
      pass: false,
      description: 'X-Frame-Options is not set and CSP frame-ancestors is not configured. Your site could be embedded in malicious iframes.',
      recommendation: "Add the header: X-Frame-Options: DENY (or SAMEORIGIN). Better yet, use CSP frame-ancestors: 'none'",
      data: {},
    };
  }

  const upper = value.toUpperCase().trim();

  if (upper === 'DENY') {
    return {
      result: 'x-frame-options-deny',
      scoreModifier: 0,
      pass: true,
      description: 'X-Frame-Options is set to DENY, preventing all framing.',
      recommendation: null,
      data: { value },
    };
  }

  if (upper === 'SAMEORIGIN') {
    return {
      result: 'x-frame-options-sameorigin',
      scoreModifier: 0,
      pass: true,
      description: 'X-Frame-Options is set to SAMEORIGIN, allowing same-origin framing only.',
      recommendation: null,
      data: { value },
    };
  }

  if (upper.startsWith('ALLOW-FROM')) {
    return {
      result: 'x-frame-options-allow-from',
      scoreModifier: -10,
      pass: false,
      description: 'X-Frame-Options uses ALLOW-FROM which is deprecated and not supported by modern browsers.',
      recommendation: "Use CSP frame-ancestors instead of ALLOW-FROM. Example: Content-Security-Policy: frame-ancestors 'self' https://trusted.example.com",
      data: { value },
    };
  }

  return {
    result: 'x-frame-options-invalid',
    scoreModifier: -20,
    pass: false,
    description: `X-Frame-Options is set to "${value}" — this is not a valid value.`,
    recommendation: 'Use "DENY" or "SAMEORIGIN".',
    data: { value },
  };
}

// ── Test 10: Cross-Origin-Resource-Policy ──

function testCORP(headers) {
  const value = headers.get('cross-origin-resource-policy');

  if (!value) {
    return {
      result: 'corp-not-implemented',
      scoreModifier: 0,
      pass: true,
      description: 'Cross-Origin-Resource-Policy is not set. Consider adding it to restrict how other origins can load your resources.',
      recommendation: 'Add the header: Cross-Origin-Resource-Policy: same-origin (or same-site if subdomains need access)',
      data: {},
    };
  }

  const lower = value.toLowerCase().trim();

  if (lower === 'same-origin') {
    return {
      result: 'corp-same-origin',
      scoreModifier: 0,
      pass: true,
      description: 'Cross-Origin-Resource-Policy is set to "same-origin". Resources are restricted to same-origin requests.',
      recommendation: null,
      data: { value },
    };
  }

  if (lower === 'same-site') {
    return {
      result: 'corp-same-site',
      scoreModifier: 0,
      pass: true,
      description: 'Cross-Origin-Resource-Policy is set to "same-site". Resources are restricted to same-site requests.',
      recommendation: null,
      data: { value },
    };
  }

  if (lower === 'cross-origin') {
    return {
      result: 'corp-cross-origin',
      scoreModifier: 0,
      pass: true,
      description: 'Cross-Origin-Resource-Policy is set to "cross-origin". Resources are accessible from any origin.',
      recommendation: 'Consider restricting to "same-origin" or "same-site" if cross-origin access is not needed.',
      data: { value },
    };
  }

  return {
    result: 'corp-invalid',
    scoreModifier: -5,
    pass: false,
    description: `Cross-Origin-Resource-Policy is set to "${value}" — not a recognized value.`,
    recommendation: 'Use "same-origin", "same-site", or "cross-origin".',
    data: { value },
  };
}

// ── Test 11: Permissions-Policy (custom bonus, not in Observatory) ──

function testPermissionsPolicy(headers) {
  const value = headers.get('permissions-policy');

  if (!value) {
    return {
      result: 'permissions-policy-not-implemented',
      scoreModifier: 0,
      pass: true,
      description: 'Permissions-Policy is not set. Browser features like camera, microphone, and geolocation are not restricted.',
      recommendation: 'Add a Permissions-Policy header: Permissions-Policy: camera=(), microphone=(), geolocation=()',
      data: {},
    };
  }

  return {
    result: 'permissions-policy-implemented',
    scoreModifier: 0,
    pass: true,
    description: 'Permissions-Policy is set, restricting browser feature access.',
    recommendation: null,
    data: { policy: value },
  };
}

// ── Informational: COOP ──

function infoCOOP(headers) {
  const value = headers.get('cross-origin-opener-policy');
  if (!value) {
    return { set: false, value: null, description: 'Cross-Origin-Opener-Policy is not set.' };
  }
  return { set: true, value, description: `Cross-Origin-Opener-Policy is set to "${value}".` };
}

// ── Informational: COEP ──

function infoCOEP(headers) {
  const value = headers.get('cross-origin-embedder-policy');
  if (!value) {
    return { set: false, value: null, description: 'Cross-Origin-Embedder-Policy is not set.' };
  }
  return { set: true, value, description: `Cross-Origin-Embedder-Policy is set to "${value}".` };
}

// ── Informational: Info Leakage ──

function infoLeakage(headers) {
  const issues = [];

  const server = headers.get('server');
  if (server && /\/\d/.test(server)) {
    issues.push({ header: 'Server', value: server, status: 'warn', description: `Server header reveals version: "${server}".` });
  } else if (server) {
    issues.push({ header: 'Server', value: server, status: 'info', description: `Server header is set to "${server}" without version details.` });
  }

  const poweredBy = headers.get('x-powered-by');
  if (poweredBy) {
    issues.push({ header: 'X-Powered-By', value: poweredBy, status: 'warn', description: `X-Powered-By reveals technology: "${poweredBy}". Remove this header.` });
  }

  const aspnet = headers.get('x-aspnet-version');
  if (aspnet) {
    issues.push({ header: 'X-AspNet-Version', value: aspnet, status: 'warn', description: `X-AspNet-Version reveals framework version: "${aspnet}". Remove this header.` });
  }

  return { issues };
}

// ── HMAC Helpers ──

async function verifyToken(token, ip, secret) {
  if (!token || typeof token !== 'string') return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;

  const timestamp = parseInt(parts[0], 10);
  if (isNaN(timestamp)) return false;

  // Token must be less than 5 minutes old
  const age = Date.now() - timestamp;
  if (age < 0 || age > 5 * 60 * 1000) return false;

  // Verify HMAC
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

  // Timing-safe comparison: re-sign both values and compare digests
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

// ── Main Handler ──

export async function onRequestPost(context) {
  const { request } = context;

  // CORS
  const origin = request.headers.get('Origin') || '';
  const corsOrigin = getAllowedOrigins(context.env).includes(origin) ? origin : getAllowedOrigins(context.env)[0];

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
  const isAllowedOrigin = getAllowedOrigins(context.env).includes(origin)
    || getAllowedOrigins(context.env).some(o => referer.startsWith(o));
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

  // ── Token Validation ──
  const scanSecret = context.env.SCAN_SECRET;
  if (!scanSecret) {
    return new Response(JSON.stringify({ error: 'Service misconfigured.' }), {
      status: 503, headers: corsHeaders,
    });
  }
  const ip = request.headers.get('CF-Connecting-IP') || '';
  const valid = await verifyToken(body.token, ip, scanSecret);
  if (!valid) {
    return new Response(JSON.stringify({ error: 'Forbidden.' }), {
      status: 403, headers: corsHeaders,
    });
  }

  // ── Rate Limiting (KV) ──
  const rateLimitKV = context.env.RATE_LIMIT;
  if (!rateLimitKV) {
    return new Response(JSON.stringify({ error: 'Service misconfigured.' }), {
      status: 503, headers: corsHeaders,
    });
  }
  {
    const rlIp = request.headers.get('CF-Connecting-IP') || 'unknown';
    const key = `rl:${rlIp}`;
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

  // Validate URL
  const validation = validateUrl(body.url);
  if (!validation.valid) {
    return new Response(JSON.stringify({ error: validation.error }), { status: 400, headers: corsHeaders });
  }

  // ── SSRF Protection: reject domains that resolve to private IPs ──
  try {
    const parsedHost = new URL(validation.url).hostname;
    if (await resolvesDangerousIP(parsedHost)) {
      return new Response(JSON.stringify({ error: 'Domain resolves to a private IP address.' }), {
        status: 400, headers: corsHeaders,
      });
    }
  } catch {
    // DoH failure — proceed cautiously (Cloudflare Workers block private IPs at fetch level)
  }

  // ── Build target URLs ──
  let httpsUrl = validation.url;
  if (httpsUrl.startsWith('http://')) {
    httpsUrl = httpsUrl.replace('http://', 'https://');
  }

  // HTTP version for redirect test
  const httpUrl = httpsUrl.replace('https://', 'http://');

  // ── Request 1 & 2: Main HTTPS GET (with body) + HTTP redirect test (parallel) ──
  let mainResult, httpRedirectResult;

  try {
    const [mainPromise, httpPromise] = await Promise.allSettled([
      followRedirects(httpsUrl, { timeout: FETCH_TIMEOUT_MS, captureBody: true }),
      followRedirects(httpUrl, { timeout: SECONDARY_TIMEOUT_MS }).catch(() => null),
    ]);

    if (mainPromise.status === 'rejected') {
      const err = mainPromise.reason;
      if (err && err.name === 'AbortError') {
        return new Response(JSON.stringify({ error: 'Request timed out. The target server did not respond within 8 seconds.' }), { status: 408, headers: corsHeaders });
      }
      return new Response(JSON.stringify({ error: 'Could not connect to the target URL. The server may be down or blocking requests.' }), { status: 502, headers: corsHeaders });
    }

    mainResult = mainPromise.value;
    httpRedirectResult = httpPromise.status === 'fulfilled' ? httpPromise.value : null;
  } catch (err) {
    if (err.name === 'AbortError') {
      return new Response(JSON.stringify({ error: 'Request timed out. The target server did not respond within 8 seconds.' }), { status: 408, headers: corsHeaders });
    }
    return new Response(JSON.stringify({ error: 'Could not connect to the target URL. The server may be down or blocking requests.' }), { status: 502, headers: corsHeaders });
  }

  const { response, finalUrl, chain: httpsChain, body: htmlBody } = mainResult;
  const headers = response.headers;

  // ── Request 3: CORS test (after main completes) ──
  let corsResponse = null;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), SECONDARY_TIMEOUT_MS);
    try {
      corsResponse = await fetch(finalUrl, {
        method: 'GET',
        headers: {
          'User-Agent': USER_AGENT,
          'Origin': 'https://evil.example.com',
        },
        redirect: 'manual',
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }
  } catch {
    // CORS test failed — will score neutral
  }

  // ── Collect Set-Cookie headers ──
  const setCookieHeaders = collectSetCookieHeaders(headers);

  // ── Run all 11 tests ──
  const hstsResult = testHSTS(headers);
  const hstsEnabled = hstsResult.scoreModifier >= 0 && hstsResult.result !== 'hsts-not-implemented';

  const cspResult = testCSP(headers, htmlBody);
  const cookiesResult = testCookies(setCookieHeaders, hstsEnabled);
  const corsResult = testCORS(corsResponse);
  const redirectionResult = testRedirection(httpsChain, httpRedirectResult);
  const referrerResult = testReferrerPolicy(headers, htmlBody);
  const sriResult = testSRI(htmlBody);
  const xContentTypeResult = testXContentTypeOptions(headers);
  const xFrameResult = testXFrameOptions(headers, cspResult);
  const corpResult = testCORP(headers);
  const permissionsPolicyResult = testPermissionsPolicy(headers);

  const tests = {
    csp: cspResult,
    cookies: cookiesResult,
    cors: corsResult,
    redirection: redirectionResult,
    'referrer-policy': referrerResult,
    hsts: hstsResult,
    sri: sriResult,
    'x-content-type-options': xContentTypeResult,
    'x-frame-options': xFrameResult,
    corp: corpResult,
    'permissions-policy': permissionsPolicyResult,
  };

  // ── Scoring: Observatory v5 algorithm ──
  // score = 100 + sum(all modifiers)
  // uncurvedScore = 100 + sum(only negative modifiers)
  // finalScore = uncurvedScore >= 90 ? score : uncurvedScore  (extra credit gating)

  let allModifiers = 0;
  let negativeModifiers = 0;
  let passCount = 0;
  let failCount = 0;

  for (const test of Object.values(tests)) {
    allModifiers += test.scoreModifier;
    if (test.scoreModifier < 0) {
      negativeModifiers += test.scoreModifier;
    }
    if (test.pass) passCount++;
    else failCount++;
  }

  const score = 100 + allModifiers;
  const uncurvedScore = 100 + negativeModifiers;
  const finalScore = uncurvedScore >= 90 ? score : uncurvedScore;
  const grade = scoreToGrade(finalScore);

  // ── Informational (not scored) ──
  const informational = {
    coop: infoCOOP(headers),
    coep: infoCOEP(headers),
    infoLeakage: infoLeakage(headers),
  };

  // ── Collect raw headers for display ──
  const rawHeaders = {};
  for (const [key, value] of headers.entries()) {
    rawHeaders[key] = value;
  }

  // ── Response ──
  const result = {
    url: validation.url,
    finalUrl,
    grade,
    score: finalScore,
    uncurvedScore,
    scannedAt: new Date().toISOString(),
    algorithmVersion: 5,
    tests,
    informational,
    rawHeaders,
    summary: {
      passCount,
      failCount,
      totalTests: Object.keys(tests).length,
    },
  };

  return new Response(JSON.stringify(result), { status: 200, headers: corsHeaders });

  } catch (err) {
    return new Response(JSON.stringify({
      error: 'An unexpected error occurred. Please try again.',
    }), { status: 500, headers: corsHeaders });
  }
}

// ── CORS preflight ──

export async function onRequestOptions(context) {
  const origin = context.request.headers.get('Origin') || '';
  if (!getAllowedOrigins(context.env).includes(origin)) {
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
