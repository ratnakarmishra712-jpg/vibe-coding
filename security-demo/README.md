# Backdoor Detection Demo Kit

A **defensive** teaching kit for one question every pentester and blue-teamer
eventually asks:

> *"Someone handed me an app. How do I tell whether it secretly captures
> credentials and phones home — and how would an antivirus see it?"*

It answers that for both shapes of the threat:

- **Web / frontend** (JavaScript in the browser) — the main focus, with two
  working scanners and a set of rogue test vectors.
- **Native / desktop** (a compiled binary, e.g. Python → `.exe`) — covered in
  the indicators and telemetry guides, since traditional antivirus sees this
  case very differently from the web one.

> **Everything here is inert and defensive.** No file captures real credentials,
> hooks password fields, logs keystrokes, or talks to a real command-and-control
> server. The "rogue" samples reproduce the *shape* of an exfiltration backdoor
> using benign payloads and reserved `*.example` placeholder hosts — the same
> idea as an EICAR test file: detectable on purpose, harmless in fact. The kit
> teaches you to **find** a backdoor, not to build one.

---

## Contents

| Path | What it is |
|------|------------|
| **`SETUP.md`** | Step-by-step install & first run. Start here. |
| `scan.sh` | **Grep scanner** — fast, zero-dependency keyword matcher. Good first pass; false-positives on comments/strings and goes blind on obfuscation. |
| `sast-scan.js` | **AST taint scanner** — parses the real code and tracks data flow from secret *sources* to network *sinks*. Catches obfuscated exfiltration grep misses. Needs Node + `npm install`. |
| `indicators.md` | The checklist both scanners encode: what each pattern is and why it matters (web **and** native). |
| `csp-and-sri.md` | The countermeasure — Content-Security-Policy + Subresource Integrity configs that *block* a frontend from exfiltrating. |
| `telemetry-and-reports.md` | Reading CSP violation reports and AV/EDR telemetry during a live engagement. |
| `sample-app/` | A benign demo login app whose "suspicious" lines live in **comments** — used to show grep's false positives vs. the AST's precision. |
| `test-fixtures/beacon.js` | A benign-but-flaggable analytics beacon that exercises the taint engine. |
| `test-fixtures/rogue-samples/` | Inert detector test vectors — one per sink (WebSocket, pixel-beacon, obfuscated `fetch`) plus a clean control that must score zero. |

---

## The two ideas the kit is built to teach

**1. Flow beats keywords.** A secret-*source* (reading a password field,
`localStorage`, `document.cookie`) and a network *sink* (`fetch`, `sendBeacon`,
`WebSocket`, a pixel `Image().src`) are each perfectly innocent on their own. A
backdoor is the **path between them**. Grep can spot the words; only data-flow
(taint) analysis spots the path — which is why obfuscation defeats one and not
the other.

**2. The detector flags the shape; the analyst judges the sensitivity.** The AST
scanner reacts to *source → sink → external host*, not to whether the data is
literally a password. A leaking shopping cart and a leaking credential produce
the same HIGH finding. The tool narrows thousands of lines to a handful of
candidate flows; a human confirms what's actually sensitive.

---

## 60-second tour

```bash
cd security-demo
npm install                       # acorn + acorn-walk (for the AST scanner)

# A) grep vs AST on the same benign file (markers live in COMMENTS)
./scan.sh sample-app              # 6 FLAGS — all false positives (text in comments)
node sast-scan.js sample-app      # 0 findings — AST ignores comments, reasons about code

# B) watch the AST scanner catch real exfiltration flows
node sast-scan.js test-fixtures/rogue-samples
#   HIGH  pixel-beacon  (feedback .value -> Image().src)
#   HIGH  obfuscated fetch to external host (minified var name, still traced)
#   MED+LOW  WebSocket send + external socket
#   (04_clean_control.js -> no findings)

# C) allowlist a known first-party host: HIGH downgrades to MED, not silenced
node sast-scan.js test-fixtures/beacon.js                          # 2 HIGH
node sast-scan.js test-fixtures/beacon.js --allow analytics.example  # -> 0 HIGH (now MED)
```

`sast-scan.js` exits non-zero when it finds a HIGH, so it drops straight into CI.

See **`SETUP.md`** for prerequisites, troubleshooting, and how to point the
scanners at a real app you've been handed.

---

## Scope & ethics

Built for authorized work: auditing an app before you trust it, security
training, and CI gating. It is detection and defense only. Use it on code you
own or are authorized to assess.
