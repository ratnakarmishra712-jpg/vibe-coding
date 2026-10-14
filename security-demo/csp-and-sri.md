# The countermeasure: CSP + SRI

This is the defensive payoff. A credential-harvesting frontend has to (a) run
code and (b) send data out. Content-Security-Policy and Subresource Integrity
make both hard.

## Content-Security-Policy — block exfiltration to unapproved origins

Serve this header (or a `<meta http-equiv>` as a fallback). `connect-src`
restricts where `fetch`/XHR/`sendBeacon`/WebSocket may send — so an implant that
tries to reach `attacker.example` is simply blocked.

```
Content-Security-Policy:
  default-src 'self';
  script-src 'self';
  connect-src 'self' https://api.your-backend.example;
  img-src 'self' data:;
  base-uri 'none';
  object-src 'none';
  frame-ancestors 'none'
```

- `script-src 'self'` (no `'unsafe-inline'`, no `'unsafe-eval'`) neutralizes
  inline `<script>` injection and `eval`/`new Function` payloads.
- `connect-src` is the exfiltration gate — list only your real backend.

### Catch it first in Report-Only mode
Deploy alongside the enforcing header to collect violations without breaking the
app:

```
Content-Security-Policy-Report-Only:
  default-src 'self'; connect-src 'self' https://api.your-backend.example;
  report-uri /csp-report
```

A backdoor beaconing out shows up as a violation report pointing at the rogue host.

## Subresource Integrity — pin third-party scripts

If you must load a script from a CDN, pin its hash so a swapped (tampered) file
won't execute:

```html
<script src="https://cdn.example/lib.js"
        integrity="sha384-BASE64_HASH_OF_THE_EXACT_FILE"
        crossorigin="anonymous"></script>
```

Compute the hash:

```bash
curl -s https://cdn.example/lib.js | openssl dgst -sha384 -binary | openssl base64 -A
```

If the CDN file changes (supply-chain attack), the hash no longer matches and the
browser refuses to run it.
