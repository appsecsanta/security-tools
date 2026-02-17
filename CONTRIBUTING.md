# Contributing to Security Tools

Thanks for your interest in contributing. This project provides free, open-source security checking tools that run on Cloudflare Pages Functions.

## Getting Started

```bash
git clone https://github.com/appsecsanta/security-tools.git
cd security-tools

# Pick a tool to work on
cd headers-checker   # or dns-checker, ssl-checker, subdomain-finder

# Install dependencies
npm install

# Start local dev server
wrangler pages dev
```

The tool will be available at `http://localhost:8788`.

## Project Structure

Each tool lives in its own directory with a self-contained Cloudflare Pages Function:

```
security-tools/
├── headers-checker/
│   └── functions/api/scan.js
├── dns-checker/
│   └── functions/api/dns-check.js
├── ssl-checker/
│   └── functions/api/ssl-check.js
└── subdomain-finder/
    └── functions/api/subdomain-finder.js
```

## Adding a New Security Test to an Existing Tool

1. Open the relevant `functions/api/*.js` file.
2. Add your test function following the existing pattern:
   ```js
   function checkNewHeader(headers) {
     const value = headers.get('new-header');
     return {
       pass: !!value,
       value: value || 'Not set',
       description: 'Brief explanation of what this test checks'
     };
   }
   ```
3. Register the test in the main handler's test array.
4. Update the scoring logic if the test affects the overall score.
5. Add the test to the relevant scoring documentation in `docs/scoring/`.
6. Write a clear commit message explaining _why_ this test matters.

## Code Style

- **Vanilla JavaScript only.** No frameworks, no build tools, no transpilation.
- **Cloudflare Pages Functions format.** Each endpoint exports an `onRequest` handler:
  ```js
  export async function onRequest(context) {
    // ...
  }
  ```
- Use `const` by default, `let` when reassignment is needed. Never `var`.
- Descriptive function names: `checkHSTS`, `validateCertChain`, not `check1` or `doStuff`.
- Handle errors explicitly. Return structured JSON with meaningful error messages.
- Keep functions small and focused. One test per function.

## Proposing a New Tool

Open an issue with the `[new-tool]` prefix that covers:

- **What it checks** -- the specific security properties being tested.
- **Why it matters** -- link to relevant RFCs, OWASP guidance, or real-world attack scenarios.
- **Scoring approach** -- how results translate to a pass/fail or numeric score.
- **External dependencies** -- any APIs or services it needs to call.

We'll discuss the scope and approach before any code is written.

## Pull Request Process

1. Fork the repo and create a branch from `main`.
2. Make your changes in a single tool directory (cross-tool PRs are harder to review).
3. Test locally with `wrangler pages dev`.
4. Open a PR with a clear description of what changed and why.

### PR Checklist

- [ ] Tests pass locally with `wrangler pages dev`
- [ ] No new external dependencies added without discussion
- [ ] Scoring documentation updated if test weights changed
- [ ] Error handling covers edge cases (timeouts, malformed input, unreachable targets)
- [ ] Response format matches existing tool output structure
- [ ] No secrets, API keys, or credentials in the code

## Reporting Bugs

Open a GitHub issue with:
- The tool name and endpoint
- Input that triggered the bug
- Expected vs. actual output
- Any relevant error messages

For security vulnerabilities, see [SECURITY.md](SECURITY.md) instead.
