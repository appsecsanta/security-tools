# Headers Checker Scoring Methodology

The headers checker evaluates HTTP response headers against 11 security tests derived from the [Mozilla Observatory v5](https://observatory.mozilla.org/) methodology and [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/).

## How Scoring Works

1. **Base score** starts at **100**.
2. Each failed test **deducts** points from the base score.
3. **Bonus points** are awarded only if the base score is **>= 90** (no bonuses for poorly configured sites).
4. Final score is clamped to a 0-100 range and mapped to a letter grade.

## Grade Scale

| Grade | Score Range |
|-------|-------------|
| A+    | 100+        |
| A     | 90 - 99     |
| A-    | 85 - 89     |
| B+    | 80 - 84     |
| B     | 70 - 79     |
| B-    | 65 - 69     |
| C+    | 60 - 64     |
| C     | 50 - 59     |
| C-    | 45 - 49     |
| D+    | 40 - 44     |
| D     | 30 - 39     |
| D-    | 20 - 29     |
| F     | 0 - 19      |

## Security Tests

### 1. Content Security Policy (CSP)

**Deduction:** -25 (missing or unsafe)

Checks for a valid `Content-Security-Policy` header. Penalizes:
- Missing CSP entirely
- Use of `unsafe-inline` or `unsafe-eval` in `script-src`
- Overly permissive `default-src` (e.g., `*`)

**Bonus:** +5 if CSP uses nonces or hashes instead of `unsafe-inline`.

**Reference:** [MDN Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy)

### 2. Cookies

**Deduction:** -20 (insecure cookies)

Checks `Set-Cookie` headers for:
- `Secure` flag (required for HTTPS)
- `HttpOnly` flag (prevents JavaScript access)
- `SameSite` attribute (CSRF protection)
- `__Host-` or `__Secure-` prefix usage

**Reference:** [RFC 6265bis](https://httpwg.org/http-extensions/draft-ietf-httpbis-rfc6265bis.html)

### 3. CORS

**Deduction:** -15 (misconfigured)

Checks `Access-Control-Allow-Origin` for:
- Wildcard (`*`) with credentials allowed
- Reflecting arbitrary origins without validation
- Overly broad origin lists

**Reference:** [MDN CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)

### 4. Redirection

**Deduction:** -10 (missing or incorrect)

Checks that HTTP requests redirect to HTTPS:
- `301` or `308` redirect from HTTP to HTTPS
- Redirect goes to the same host (no open redirect)
- No intermediate HTTP hops in the redirect chain

### 5. Referrer-Policy

**Deduction:** -5 (missing or unsafe)

Checks for a `Referrer-Policy` header with a restrictive value:
- `no-referrer`
- `same-origin`
- `strict-origin`
- `strict-origin-when-cross-origin`

**Bonus:** +5 for `no-referrer` or `same-origin`.

**Reference:** [MDN Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy)

### 6. Strict-Transport-Security (HSTS)

**Deduction:** -25 (missing or weak)

Checks for an HSTS header with:
- `max-age` of at least 6 months (15768000 seconds)
- `includeSubDomains` directive

**Bonus:** +5 for HSTS preload (`preload` directive with `max-age` >= 1 year).

**Reference:** [RFC 6797](https://www.rfc-editor.org/rfc/rfc6797)

### 7. Subresource Integrity (SRI)

**Deduction:** -5 (missing on external scripts/styles)

Checks that `<script>` and `<link>` tags loading from external origins include `integrity` attributes.

**Reference:** [MDN Subresource Integrity](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity)

### 8. X-Content-Type-Options

**Deduction:** -10 (missing)

Checks for `X-Content-Type-Options: nosniff` to prevent MIME-type sniffing.

**Reference:** [MDN X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options)

### 9. X-Frame-Options

**Deduction:** -10 (missing)

Checks for `X-Frame-Options` set to `DENY` or `SAMEORIGIN`. Also passes if CSP includes a `frame-ancestors` directive.

**Reference:** [RFC 7034](https://www.rfc-editor.org/rfc/rfc7034)

### 10. Cross-Origin-Resource-Policy (CORP)

**Deduction:** -5 (missing)

Checks for `Cross-Origin-Resource-Policy` header set to `same-origin` or `same-site`.

**Reference:** [MDN Cross-Origin-Resource-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy)

### 11. Permissions-Policy

**Deduction:** -5 (missing)

Checks for a `Permissions-Policy` header that restricts browser features (camera, microphone, geolocation, etc.).

**Bonus:** +5 for restricting all sensitive features to `self` or `none`.

**Reference:** [W3C Permissions Policy](https://w3c.github.io/webappsec-permissions-policy/)

## Score Calculation Example

A site with:
- Valid CSP with nonces: 0 deduction, +5 bonus
- Missing HSTS: -25 deduction
- Everything else passing: 0 deduction

Base score: 100 - 25 = 75. Bonus not applied (base < 90). **Final score: 75 (B)**.

## References

- [Mozilla Observatory v5 Scoring](https://observatory.mozilla.org/)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [OWASP HTTP Security Response Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
