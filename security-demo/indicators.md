# Indicators of a credential-harvesting frontend backdoor

Use these when auditing an app someone handed you. None is proof on its own — a
flag is a *lead* to trace back to a legitimate reason or to a problem.

## 1. Reading what the user types
- `addEventListener('input' | 'keydown' | 'keyup' | 'keypress', ...)` on or near
  form fields.
- Direct references to `input[type=password]`, field `name`/`id` of password or
  token inputs, or serializing a whole `FormData` and keeping the values.
- **Legit reasons exist** (validation, strength meters). Check where the value
  *goes* next — that's what matters.

## 2. Reading stored secrets
- `localStorage` / `sessionStorage` / `document.cookie` reads, especially keys
  named `token`, `auth`, `jwt`, `session`.

## 3. Sending data out
- `fetch` / `XMLHttpRequest` / `navigator.sendBeacon` / `new WebSocket` to a host
  that is **not the app's own backend**.
- Hardcoded raw IPs, odd TLDs, URL-shorteners, or an image/pixel whose `src` is
  built from field values (a beacon in disguise).
- `sendBeacon` is a favorite: it fires on page unload and is easy to miss in the
  Network tab.

## 4. Hiding the payload
- `eval(...)`, `new Function(...)`, `atob(...)` feeding into execution — dynamic
  code from a string.
- A minified/obfuscated blob that doesn't match the style of the rest of the code.
- A bundled dependency whose contents differ from its published npm version
  (supply-chain tampering).

## How to confirm at runtime
1. Open devtools → **Network**, check "Preserve log", interact with the app, and
   watch for requests to unexpected hosts — including on page unload.
2. Set a **Content-Security-Policy in `Report-Only` mode** (see `csp-and-sri.md`)
   and read the violation reports; a backdoor's exfiltration shows up as a
   blocked/reported connection to a disallowed origin.
3. Diff vendored dependencies against the registry (`npm pack` the pinned version
   and compare).
