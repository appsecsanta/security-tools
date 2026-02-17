# DNS Checker Scoring Methodology

The DNS checker evaluates 8 DNS security properties using a weighted scoring system. Each test adds or deducts points from a base of 0, with a maximum possible score of 100.

## Scoring System

Each test has a fixed weight. A passing test adds its full weight to the score. A failing test deducts the same amount. The final score is clamped to 0-100.

| Test | Pass | Fail | Weight |
|------|------|------|--------|
| DNSSEC | +15 | -15 | 15 |
| SPF | +15 | -15 | 15 |
| DMARC | +15 | -15 | 15 |
| CAA | +10 | -10 | 10 |
| NS Redundancy | +10 | -10 | 10 |
| MX Records | +10 | -10 | 10 |
| Zone Transfer | +10 | -10 | 10 |
| Dangling CNAME | +15 | -15 | 15 |

**Maximum score:** 100 (all tests pass)
**Minimum score:** 0 (clamped; raw minimum is -100)

## Security Tests

### 1. DNSSEC (Weight: 15)

**Pass:** Domain has a valid DNSSEC chain of trust (DS and RRSIG records present and verifiable).

**Fail:** No DNSSEC, broken chain of trust, or expired signatures.

DNSSEC prevents DNS spoofing and cache poisoning by cryptographically signing DNS responses.

**Reference:** [RFC 4033](https://www.rfc-editor.org/rfc/rfc4033) (DNSSEC Introduction), [RFC 4034](https://www.rfc-editor.org/rfc/rfc4034) (Resource Records), [RFC 4035](https://www.rfc-editor.org/rfc/rfc4035) (Protocol Modifications)

### 2. SPF (Weight: 15)

**Pass:** Valid `TXT` record with SPF policy (`v=spf1 ...`) that ends with `-all` or `~all`.

**Fail:** No SPF record, multiple SPF records, or policy ends with `+all`.

SPF specifies which mail servers are authorized to send email on behalf of a domain, reducing email spoofing.

**Reference:** [RFC 7208](https://www.rfc-editor.org/rfc/rfc7208)

### 3. DMARC (Weight: 15)

**Pass:** Valid `_dmarc` TXT record with at least `p=quarantine` or `p=reject`.

**Fail:** No DMARC record, or policy is `p=none` without a `rua` reporting address.

DMARC builds on SPF and DKIM to provide email authentication and reporting.

**Reference:** [RFC 7489](https://www.rfc-editor.org/rfc/rfc7489)

### 4. CAA (Weight: 10)

**Pass:** Domain has CAA records specifying authorized Certificate Authorities.

**Fail:** No CAA records found.

CAA records prevent unauthorized CAs from issuing certificates for a domain.

**Reference:** [RFC 8659](https://www.rfc-editor.org/rfc/rfc8659)

### 5. NS Redundancy (Weight: 10)

**Pass:** Domain has at least 2 nameservers on different network prefixes.

**Fail:** Single nameserver, or all nameservers on the same /24 network.

Multiple nameservers on diverse networks ensure DNS availability during outages.

**Reference:** [RFC 2182](https://www.rfc-editor.org/rfc/rfc2182) (Selection and Operation of Secondary DNS Servers)

### 6. MX Records (Weight: 10)

**Pass:** Domain has valid MX records pointing to reachable mail servers.

**Fail:** No MX records, or MX records point to unreachable or invalid hosts.

Properly configured MX records ensure reliable email delivery and are a baseline DNS hygiene check.

### 7. Zone Transfer (Weight: 10)

**Pass:** AXFR requests are refused by all nameservers.

**Fail:** At least one nameserver allows zone transfer to arbitrary requesters.

Open zone transfers expose the complete DNS zone file, revealing internal hostnames and network structure.

**Reference:** [RFC 5936](https://www.rfc-editor.org/rfc/rfc5936) (DNS Zone Transfer Protocol)

### 8. Dangling CNAME (Weight: 15)

**Pass:** All CNAME records resolve to active targets.

**Fail:** One or more CNAME records point to non-existent or unclaimed resources (subdomain takeover risk).

Dangling CNAMEs can be exploited for subdomain takeover attacks when the target service is deprovisioned but the DNS record remains.

## Score Calculation Example

A domain with:
- DNSSEC enabled: +15
- Valid SPF: +15
- No DMARC: -15
- CAA present: +10
- 2 nameservers on different networks: +10
- Valid MX records: +10
- Zone transfer refused: +10
- No dangling CNAMEs: +15

**Final score:** 15 + 15 - 15 + 10 + 10 + 10 + 10 + 15 = **70**

## References

- [NIST SP 800-81-2](https://csrc.nist.gov/publications/detail/sp/800-81/2/final) -- Secure DNS Deployment Guide
- [RFC 7208](https://www.rfc-editor.org/rfc/rfc7208) -- SPF
- [RFC 7489](https://www.rfc-editor.org/rfc/rfc7489) -- DMARC
- [RFC 8659](https://www.rfc-editor.org/rfc/rfc8659) -- CAA
- [RFC 4033-4035](https://www.rfc-editor.org/rfc/rfc4033) -- DNSSEC
