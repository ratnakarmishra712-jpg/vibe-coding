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
| `scan.sh` | Static-analysis scanner. Greps a directory for backdoor indicators and prints a report. |
| `indicators.md` | The checklist of what the scanner looks for and why each pattern matters. |
| `csp-and-sri.md` | The actual countermeasure: Content-Security-Policy + Subresource Integrity configs that block a frontend from exfiltrating to unapproved origins. |

## Run the demo

```bash
cd security-demo
./scan.sh sample-app
```

You should see the scanner flag the marker lines in `sample-app/app.js` with an
explanation for each. Then read `indicators.md` and `csp-and-sri.md` to see how a
reviewer reasons about the hits and how CSP/SRI would have stopped a real implant.
