# SSL Checker Scoring Methodology

The SSL checker evaluates 8 TLS/SSL security properties using a weighted scoring system. Each test adds or deducts points, with a maximum possible score of 100.

## Scoring System

Each test has independent pass/fail weights. Some tests deduct more on failure than they award on pass (e.g., HTTPS Available) to reflect the severity of the issue.

| Test | Pass | Fail | Weight |
|------|------|------|--------|
| HTTPS Available | +15 | -20 | 15 |
| HTTP Redirect | +10 | -10 | 10 |
| HSTS | +15 | -15 | 15 |
| Certificate Expiry | +15 | -15 | 15 |
| CT Logs | +10 | -10 | 10 |
| Chain of Trust | +15 | -15 | 15 |
| DANE/TLSA | +5 | 0 | 5 |
| Mixed Content | +15 | -15 | 15 |

**Maximum score:** 100 (all tests pass)
**Minimum score:** 0 (clamped)

**Note:** DANE/TLSA has no deduction on failure because adoption is still limited. It acts as a bonus for sites that implement it.

## Security Tests

### 1. HTTPS Available (Pass: +15 / Fail: -20)

**Pass:** Site responds successfully over HTTPS (port 443) with a valid TLS handshake.

**Fail:** No HTTPS listener, TLS handshake failure, or only SSLv3/TLS 1.0/1.1 available.

The asymmetric weighting (-20 on fail) reflects that missing HTTPS is a fundamental security failure that undermines all other checks.

**Reference:** [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) (TLS 1.3)

### 2. HTTP Redirect (Pass: +10 / Fail: -10)

**Pass:** HTTP (port 80) returns a `301` or `308` redirect to the HTTPS version of the same host.

**Fail:** HTTP serves content without redirecting, redirects to a different host, or HTTP port is unreachable.

**Reference:** [RFC 7538](https://www.rfc-editor.org/rfc/rfc7538) (308 Permanent Redirect)

### 3. HSTS (Pass: +15 / Fail: -15)

**Pass:** `Strict-Transport-Security` header present with:
- `max-age` >= 15768000 (6 months)
- `includeSubDomains` directive recommended

**Fail:** Missing HSTS header or `max-age` below threshold.

HSTS ensures browsers always connect via HTTPS, preventing protocol downgrade attacks.

**Reference:** [RFC 6797](https://www.rfc-editor.org/rfc/rfc6797)

### 4. Certificate Expiry (Pass: +15 / Fail: -15)

**Pass:** Certificate is currently valid and does not expire within 14 days.

**Fail:** Certificate is expired, not yet valid, or expires within 14 days.

Short-lived certificates (< 14 days remaining) are flagged as a warning since they indicate potential renewal issues.

**Reference:** [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) (X.509 PKI)

### 5. Certificate Transparency Logs (Pass: +10 / Fail: -10)

**Pass:** Certificate includes Signed Certificate Timestamps (SCTs) via the TLS extension, a stapled OCSP response, or embedded in the certificate itself.

**Fail:** No SCTs found through any delivery mechanism.

Certificate Transparency provides an auditable log of issued certificates, making misissued certificates detectable.

**Reference:** [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) (Certificate Transparency)

### 6. Chain of Trust (Pass: +15 / Fail: -15)

**Pass:** Complete certificate chain is served, chain terminates at a trusted root CA, and no intermediate certificates are missing.

**Fail:** Incomplete chain, self-signed certificate (non-root), untrusted root CA, or revoked intermediate.

A broken chain of trust causes connection failures in strict TLS clients and indicates a misconfigured server.

**Reference:** [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) (Certificate Path Validation)

### 7. DANE/TLSA (Pass: +5 / Fail: 0)

**Pass:** Domain publishes TLSA records in DNS (requires DNSSEC) that match the served certificate.

**Fail:** No TLSA records found. No deduction -- this is a bonus-only test.

DANE (DNS-Based Authentication of Named Entities) allows domain owners to specify which certificates are valid for their domain via DNS, reducing reliance on the CA ecosystem.

**Reference:** [RFC 6698](https://www.rfc-editor.org/rfc/rfc6698) (DANE), [RFC 7671](https://www.rfc-editor.org/rfc/rfc7671) (DANE Updates)

### 8. Mixed Content (Pass: +15 / Fail: -15)

**Pass:** Page served over HTTPS loads all subresources (scripts, stylesheets, images, iframes) over HTTPS.

**Fail:** One or more subresources loaded over plain HTTP.

Mixed content undermines HTTPS by allowing attackers to tamper with insecure subresources on an otherwise encrypted page. Active mixed content (scripts, iframes) is especially dangerous.

**Reference:** [W3C Mixed Content](https://www.w3.org/TR/mixed-content/)

## Score Calculation Example

A site with:
- HTTPS available (TLS 1.3): +15
- HTTP redirects to HTTPS: +10
- HSTS with 1-year max-age: +15
- Certificate valid, expires in 90 days: +15
- SCTs present in certificate: +10
- Full chain served, trusted root: +15
- No DANE/TLSA records: 0
- No mixed content: +15

**Final score:** 15 + 10 + 15 + 15 + 10 + 15 + 0 + 15 = **95**

## References

- [OWASP TLS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)
- [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) -- TLS 1.3
- [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) -- Certificate Transparency
- [RFC 6797](https://www.rfc-editor.org/rfc/rfc6797) -- HSTS
- [RFC 6698](https://www.rfc-editor.org/rfc/rfc6698) -- DANE
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
