# Frontend Backdoor — Detection Demo Kit

A **defensive** teaching demo for the scenario: *"Someone hands me a frontend-only
app. How do I tell whether it secretly captures credentials and phones home?"*

Everything in this kit is **inert**:

- No real or fake credentials are ever captured.
- No `input`/`keydown`/`submit` listeners read password or token fields.
- No `fetch` / `XMLHttpRequest` / `sendBeacon` / WebSocket sends data anywhere.
- The only "suspicious" content is **marker strings** in `sample-app/`, placed
  so you can watch the scanner light them up.

This kit teaches you to *find* a credential-harvesting backdoor, not to build one.

## Contents

| File | Purpose |
|------|---------|
| `sample-app/index.html` | A benign demo page with a login form. Inert. |
| `sample-app/app.js` | Benign app logic. Contains commented **marker strings** a scanner should flag — but no working exfiltration. |
| `scan.sh` | Grep-based indicator scanner. Fast, zero-dependency — but matches text, so it false-positives on comments/strings. |
| `sast-scan.js` | **AST-based taint scanner.** Parses the real code and tracks data flow from SOURCES (reading secrets) to SINKS (network calls). Flags source→sink flows and external destinations. Needs `npm install`. |
| `test-fixtures/beacon.js` | A benign-but-flaggable fixture (an analytics beacon — *not* a stealer) to exercise the taint engine. |
| `indicators.md` | The checklist of what the scanners look for and why each pattern matters. |
| `csp-and-sri.md` | Countermeasure: Content-Security-Policy + Subresource Integrity configs that block a frontend from exfiltrating to unapproved origins. |
| `telemetry-and-reports.md` | How to read CSP violation reports and AV/EDR telemetry during a live engagement. |

## grep vs. AST — the lesson

Run both against `sample-app/` (whose "suspicious" markers live in **comments**):

- `scan.sh sample-app` → flags **6** patterns (all false positives — text in comments).
- `node sast-scan.js sample-app` → **0** findings (the AST doesn't see comments; it reasons about executable code and real data flow).

Then run the AST scanner against the fixture to see it catch genuine flows, and
watch the allowlist downgrade HIGH→MED instead of silencing:

```bash
npm install                                   # acorn + acorn-walk
node sast-scan.js test-fixtures               # 2 HIGH: tainted data -> external host
node sast-scan.js test-fixtures --allow analytics.example   # downgraded to MED
```

## Run the demo

```bash
cd security-demo
./scan.sh sample-app
```

You should see the scanner flag the marker lines in `sample-app/app.js` with an
explanation for each. Then read `indicators.md` and `csp-and-sri.md` to see how a
reviewer reasons about the hits and how CSP/SRI would have stopped a real implant.
