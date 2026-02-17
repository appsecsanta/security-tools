# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

**Email:** [security@appsecsanta.com](mailto:security@appsecsanta.com)

**Expected response time:** We will acknowledge your report within **48 hours** and provide an initial assessment within 5 business days.

### What to Include

- Description of the vulnerability and its potential impact
- Steps to reproduce (the more detail, the better)
- Affected tool(s) and endpoint(s)
- Your suggested fix, if you have one

### What Qualifies as a Vulnerability

We consider these security vulnerabilities:

- **Server-Side Request Forgery (SSRF)** -- Ability to make the tool scan internal/private IP ranges or cloud metadata endpoints
- **Injection attacks** -- Code injection, header injection, or DNS rebinding through scan inputs
- **Authentication/authorization bypass** -- Circumventing rate limits, API keys, or origin restrictions
- **Information disclosure** -- Leaking server internals, environment variables, or other users' scan results
- **Denial of service** -- Input that crashes the worker or causes excessive resource consumption

### What Does NOT Qualify

These are regular bugs, not security vulnerabilities. Please file a GitHub issue instead:

- Incorrect scan results or scoring errors
- UI rendering issues
- Broken links or typos in documentation
- Feature requests
- Tools correctly reporting that a target has poor security

## Safe Harbor

We support responsible security research. If you act in good faith and follow this policy, we commit to:

- **Not pursuing legal action** against you for your research
- **Not reporting your activity** to law enforcement for research conducted under this policy
- **Working with you** to understand and resolve the issue quickly
- **Crediting you** in the fix (unless you prefer to remain anonymous)

To qualify for safe harbor:

- Report the vulnerability promptly after discovery
- Avoid accessing, modifying, or deleting data that doesn't belong to you
- Don't degrade the service for other users
- Don't scan third-party targets using a vulnerability in our tools
- Give us reasonable time to fix the issue before any public disclosure

## Scope

This policy covers all code in this repository, including:

- Cloudflare Pages Functions (API endpoints)
- Scoring logic and test implementations
- Rate limiting and input validation

Infrastructure that is **out of scope** (report to the respective provider instead):

- Cloudflare's platform itself
- Third-party DNS resolvers or certificate transparency logs
- The targets being scanned by the tools

## Disclosure Timeline

1. You report the vulnerability.
2. We acknowledge within 48 hours.
3. We assess severity and develop a fix (target: 14 days for critical, 30 days for others).
4. We deploy the fix and notify you.
5. We coordinate public disclosure timing with you.
