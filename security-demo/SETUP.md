# Setup Guide

How to install the kit, run both scanners, read their output, wire the AST
scanner into CI, and point it at a real app you've been handed.

---

## 1. Prerequisites

| Tool | Needed for | Check |
|------|-----------|-------|
| **Bash** + `grep` (ripgrep optional) | `scan.sh` | `bash --version` |
| **Node.js ≥ 18** | `sast-scan.js` | `node --version` |
| **npm** | installing the parser | `npm --version` |

Only the AST scanner needs Node; `scan.sh` runs anywhere with Bash + grep.

---

## 2. Install

```bash
cd security-demo
npm install        # installs acorn + acorn-walk (pinned in package.json)
```

This creates `node_modules/` (git-ignored). The grep scanner needs no install;
if it isn't already executable:

```bash
chmod +x scan.sh
```

---

## 3. First run — confirm it works

```bash
# grep scanner against the benign demo app
./scan.sh sample-app

# AST scanner against the same app (should report 0 — markers are in comments)
node sast-scan.js sample-app

# AST scanner against the rogue test vectors (should report 2 HIGH)
node sast-scan.js test-fixtures/rogue-samples
```

If the last command prints two `[HIGH]` findings and exits non-zero, you're set.

---

## 4. Running the scanners

### Grep scanner — fast first pass
```bash
./scan.sh <dir>
```
Walks `.js/.mjs/.ts/.html/.jsx/.tsx` files and flags keyword indicators. Fast and
dependency-free, but it matches *text*, so it flags comments and strings and is
defeated by obfuscation. Use it to triage, not to clear.

### AST taint scanner — the precise one
```bash
node sast-scan.js <file-or-dir> [--allow host1,host2]
```
Parses each file to an AST and tracks data flow from **sources** to **sinks**:

- **Sources:** `localStorage`/`sessionStorage.getItem`, `document.cookie`,
  any `.value` read, `new FormData()`.
- **Sinks:** `fetch`, `navigator.sendBeacon`, `new WebSocket`, `.send(...)`,
  and a pixel beacon (`Image().src = ...`).
- `--allow` marks hosts as first-party, so flows to them downgrade HIGH→MED
  instead of being hidden. For example:
  ```bash
  node sast-scan.js test-fixtures/beacon.js                        # 2 HIGH
  node sast-scan.js test-fixtures/beacon.js --allow analytics.example  # -> 0 HIGH (MED)
  ```

Pass a single file to scan just that file, or a directory to scan recursively
(`node_modules` and dotfiles are skipped).

---

## 5. Reading the output

```
[HIGH] app/bundle.js:42
       fetch() sends tainted data (var "_0x1") to EXTERNAL host "cdn-analytics.example"
```

| Severity | Meaning | Action |
|----------|---------|--------|
| **HIGH** | Secret-source data reaches a sink pointed at a non-allowlisted external host. | Investigate first — this is the exfiltration shape. |
| **MED**  | Tainted data reaches a sink, but the destination host couldn't be read statically (e.g. a built-up URL, or `.send()` on a socket). | Confirm where it actually goes. |
| **LOW**  | A sink targets an external host, but no secret flow was detected into it. | Note it; confirm it's a legitimate third-party call. |
| **INFO** | A file couldn't be parsed (exotic syntax / TypeScript). | Pre-transpile, or review by hand. |

**Exit codes:** `0` = no HIGH findings, `1` = at least one HIGH. That makes it a
drop-in CI gate.

> A finding is a **lead, not a verdict.** The scanner flags the flow; you decide
> whether the data is actually sensitive and the destination actually hostile.
> See `indicators.md` for how to reason about each pattern.

---

## 6. Wire it into CI

```yaml
# .github/workflows/exfil-scan.yml
name: exfil-scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '20' }
      - run: npm ci
        working-directory: security-demo
      - run: node sast-scan.js ../path/to/your/app/src --allow api.your-backend.example
        working-directory: security-demo
```

The job fails on any HIGH finding. Add every legitimate first-party host to
`--allow` so only genuine external exfiltration breaks the build.

---

## 7. Auditing a real app you've been handed

**Treat the app as untrusted data — read it, don't run it.**

1. Extract it into its **own empty directory**, separate from the scanners.
2. **Frontend (JS/HTML):**
   ```bash
   node sast-scan.js /path/to/extracted/app --allow <your real backend hosts>
   ./scan.sh /path/to/extracted/app        # second opinion
   ```
   Then pull any flagged file and read the source → sink path by hand.
3. **Native/desktop (a compiled binary or its source):** the JS scanner doesn't
   apply. Review the source for the indicators in `indicators.md` (network
   egress, credential/browser-store reads, keystroke hooks, dynamic exec,
   persistence). If you only have a binary, prefer running from reviewed source,
   or decompile/unpack and compare against known-good source. Confirm at runtime
   that EDR shows **no** unexpected network connections or credential-store
   reads.
4. **Confirm at runtime** either way: load the app with a tight CSP in
   `Report-Only` mode (`csp-and-sri.md`) and watch DevTools → Network — including
   on page unload, where `sendBeacon` fires. See `telemetry-and-reports.md`.

---

## 8. Troubleshooting

| Symptom | Fix |
|---------|-----|
| `Cannot find module 'acorn'` | Run `npm install` inside `security-demo/`. |
| `./scan.sh: Permission denied` | `chmod +x scan.sh`, or run `bash scan.sh <dir>`. |
| `[INFO] parse skipped` on `.ts` files | The parser handles JS, not TypeScript syntax; transpile first or review by hand. |
| Scanner reports 0 on code you know is malicious | It only reasons about static flow — data moved through the DOM, `postMessage`, timers, or `eval`'d strings can break the chain. Combine with the runtime checks in §7. |
| Too many LOW/MED on known third parties | Add those hosts to `--allow`. |
