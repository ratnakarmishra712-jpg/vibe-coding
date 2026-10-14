# Rogue-sample test vectors (INERT)

Detector test cases for `sast-scan.js`. Each file reproduces the **shape** of an
exfiltration backdoor — a secret-source API whose data flows into a network sink
pointed at an external host — so you can watch the scanner catch it.

They are deliberately **inert and benign**:

- The "stolen" data is mundane (a cart, a theme, feedback text, UI prefs), not
  credentials. The scanner fires on the *flow*, which is identical either way —
  that's the whole lesson.
- Destinations are `*.example` placeholders (reserved, non-routable).
- No password-field hooking, keylogging, or real command-and-control.

This is the same idea as an EICAR test file: detectable on purpose, harmless in
fact. Run `node ../../sast-scan.js .` from here (or `node sast-scan.js
test-fixtures/rogue-samples` from the kit root).
