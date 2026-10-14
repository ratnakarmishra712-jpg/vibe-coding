#!/usr/bin/env bash
# nfqueue_setup.sh — add/remove the iptables rule that feeds packets to ngfw's
# NFQUEUE backend. Linux + root only.
#
#   sudo ./nfqueue_setup.sh up    [queue_num]   # start sending traffic to the queue
#   sudo ./nfqueue_setup.sh down  [queue_num]   # remove the rule (ALWAYS run when done)
#   sudo ./nfqueue_setup.sh status
#
# SAFETY NOTES — read before using 'up':
#   * We add the rule with --queue-bypass (FAIL OPEN): if ngfw isn't running,
#     packets pass normally, so a crash can't cut your network.
#   * By default we queue a NARROW slice (one test port) so you can't lock
#     yourself out. Edit TEST_MATCH below to widen it deliberately.
#   * NEVER enforce-drop on the interface/port carrying your SSH session.
#   * If something goes wrong, 'sudo iptables -F' clears all rules; on a remote
#     box keep a second console or an out-of-band path open first.
set -euo pipefail

QNUM="${2:-0}"
# Narrow test scope: only TCP to port 9999 goes to the queue. Widen on purpose.
TEST_MATCH=(-p tcp --dport 9999)
CHAIN=INPUT

if [[ $EUID -ne 0 ]]; then echo "run as root (sudo)"; exit 1; fi
command -v iptables >/dev/null || { echo "iptables not found"; exit 1; }

case "${1:-}" in
  up)
    iptables -I "$CHAIN" "${TEST_MATCH[@]}" -j NFQUEUE --queue-num "$QNUM" --queue-bypass
    echo "queued: $CHAIN ${TEST_MATCH[*]} -> NFQUEUE $QNUM (fail-open)."
    echo "now run:  sudo python3 -m ngfw --nfqueue $QNUM --home <your-ip>/32"
    echo "          (add --enforce only when ready to actually drop)"
    echo "REMEMBER:  sudo $0 down $QNUM   when finished."
    ;;
  down)
    iptables -D "$CHAIN" "${TEST_MATCH[@]}" -j NFQUEUE --queue-num "$QNUM" --queue-bypass \
      && echo "removed the NFQUEUE rule." || echo "rule not present (nothing to remove)."
    ;;
  status)
    iptables -S "$CHAIN" | grep -i nfqueue || echo "no NFQUEUE rules in $CHAIN."
    ;;
  *)
    echo "usage: sudo $0 {up|down|status} [queue_num]"; exit 2;;
esac
