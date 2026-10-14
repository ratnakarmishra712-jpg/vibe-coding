# Reading the signals during an engagement

How to actually *watch for* a credential-harvesting/exfiltration backdoor at
runtime — the web stack first (your scenario), then the endpoint stack. All
defensive: you're consuming telemetry the platforms already produce.

## A. CSP violation reports — the web early-warning system

Content-Security-Policy can run in **Report-Only** mode: it doesn't block
anything, it just *reports* every action that *would* have violated the policy.
Deploy a tight policy in report-only and you get a feed of attempted
exfiltration without breaking the app.

Header:
```
Content-Security-Policy-Report-Only:
  default-src 'self';
  connect-src 'self' https://api.your-backend.example;
  report-to csp-endpoint
Report-To: {"group":"csp-endpoint","max_age":10886400,
            "endpoints":[{"url":"https://your-collector.example/csp"}]}
```

A backdoor beaconing to `analytics.example` or `attacker.example` produces a
report like:
```json
{
  "type": "csp-violation",
  "body": {
    "documentURL": "https://app.example/login",
    "effectiveDirective": "connect-src",
    "blockedURL": "https://attacker.example/collect",
    "disposition": "report",
    "sourceFile": "https://app.example/app.js",
    "lineNumber": 42
  }
}
```

**How to read it:**
- `effectiveDirective: connect-src` + a `blockedURL` you don't recognize = an
  exfiltration attempt. The `blockedURL` host is the C2/collector.
- `sourceFile` + `lineNumber` point you straight at the offending code — feed
  that file to `sast-scan.js`.
- `effectiveDirective: script-src` with an inline/`eval` violation = dynamic code
  execution (the "hiding the payload" category).
- Triage out the noise first: browser extensions and some analytics SDKs
  generate benign `connect-src`/`img-src` reports. Allowlist the known-good hosts
  (same idea as `--allow` in the scanner), and what remains is signal.

Then flip the same policy from `-Report-Only` to enforcing and the exfiltration
is *blocked*, not just logged.

## B. Network-layer confirmation

- **DevTools → Network**, "Preserve log" on, interact + navigate away. Watch for
  requests to unexpected hosts — especially `sendBeacon`, which fires on unload
  and is easy to miss. Sort by Domain; anything that isn't your backend or a
  known SDK is a lead.
- **Web proxy / CASB / egress logs** give you the same view fleet-wide: new or
  rare destination domains, young domains, requests carrying base64-ish blobs in
  the body or query string.

## C. Endpoint telemetry (the native-stealer case)

For compiled stealers, you're reading EDR/OS telemetry instead of CSP. The
highest-signal events — because they capture the *behavior* the malware can't
skip:

| Signal source | What to look for |
|---------------|------------------|
| **File access auditing** (EDR / Sysmon FileCreate+read, macOS ESF) | A process reading browser profile/credential-store paths it has no business touching |
| **Process creation** (Sysmon ID 1 / EDR) | Short-lived helpers, LOLBins (`powershell -enc`, `certutil`, `bitsadmin`) spawned by an app |
| **Network connection** (Sysmon ID 3 / EDR) | A just-written unsigned binary making outbound connections to a young/rare domain |
| **Module/image load** (Sysmon ID 7) | Unsigned or injected DLLs loading into a browser or trusted process |
| **AV/EDR detections feed** | Signature + heuristic + behavioral verdicts; read the *reason* field, not just the verdict |

**The through-line:** static identity can be disguised, but the *action* —
reading the secret, then sending it out — is what both stacks are built to
observe. On the web that action is a `connect-src` violation; on the endpoint
it's a credential-store read followed by an outbound connection. Instrument
those two choke points and the "undetectable" implant has nowhere to hide its
actual job.

## D. During a real engagement — a short workflow

1. Deploy CSP **Report-Only** with a tight `connect-src`; collect reports.
2. Pull the `sourceFile`s named in violations and run `sast-scan.js` on the
   bundle to find the source→sink flow.
3. Confirm live in DevTools/proxy (watch unload beacons).
4. For any binaries in scope, pull EDR file-read + network + process telemetry
   around the suspected host.
5. Remediate: flip CSP to enforcing, add SRI pins, and (endpoint) block/kill the
   binary and rotate any credentials that were in scope.
