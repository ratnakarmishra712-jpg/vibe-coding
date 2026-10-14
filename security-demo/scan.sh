#!/usr/bin/env bash
# scan.sh — static indicator scanner for a shared frontend app (DEFENSIVE).
#
# Greps a directory for patterns commonly seen in credential-harvesting or
# exfiltration backdoors. It only READS files and prints a report. It does not
# modify, execute, or transmit anything.
#
# Usage: ./scan.sh <dir>
set -euo pipefail

DIR="${1:-.}"
if [[ ! -d "$DIR" ]]; then
  echo "usage: $0 <dir-to-scan>" >&2
  exit 2
fi

# pattern | human-readable reason
declare -a CHECKS=(
  'sendBeacon|navigator.sendBeacon — fire-and-forget exfiltration, survives page unload'
  'new WebSocket|outbound WebSocket — a persistent channel to a remote host'
  "addEventListener\\(['\"]?(input|keydown|keyup|keypress)|keystroke/input listener — may be reading what is typed"
  "input\\[type=?['\"]?password|direct reference to password fields"
  'localStorage|sessionStorage|document\.cookie|reads browser-stored tokens/cookies'
  '\batob\b|\bbtoa\b|base64 encode/decode — often hides payloads or staged data'
  '\beval\(|new Function\(|dynamic code execution from a string'
  'https?://[0-9]{1,3}(\.[0-9]{1,3}){3}|hardcoded raw IP endpoint'
  'fetch\(|XMLHttpRequest|outbound request — confirm the host is the app'"'"'s own backend'
)

echo "== Backdoor indicator scan: $DIR =="
echo "(matches are LEADS to review, not proof of malice)"
echo

hits=0
while IFS= read -r -d '' f; do
  for entry in "${CHECKS[@]}"; do
    pat="${entry%%|*}"
    reason="${entry#*|}"
    if grep -nEI "$pat" "$f" >/dev/null 2>&1; then
      echo "[FLAG] $f"
      echo "       why: $reason"
      grep -nEI "$pat" "$f" | sed 's/^/       /'
      echo
      hits=$((hits+1))
    fi
  done
done < <(find "$DIR" -type f \( -name '*.js' -o -name '*.mjs' -o -name '*.ts' -o -name '*.html' -o -name '*.jsx' -o -name '*.tsx' \) -print0)

echo "== done: $hits flagged pattern(s). Review each against indicators.md =="
