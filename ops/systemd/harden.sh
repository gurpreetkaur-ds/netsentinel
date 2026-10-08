#!/usr/bin/env bash
# Applies the NetSentinel service sandbox and the dashboard's modern-cipher setting.
# Run as root:  sudo bash ~/netsentinel/ops/systemd/harden.sh
#
# What it changes:
#   - adds drop-ins /etc/systemd/system/netsentinel-<svc>.service.d/hardening.conf (+ python-only.conf for
#     all but the Investigation Agent): no device/kernel/cgroup access, no new privileges or capabilities,
#     invisible /proc of other processes, read-only home except the paths each unit already allows,
#     restricted syscalls/address families. Unit files themselves are not edited.
#   - restarts each service ONE AT A TIME; if a service is not healthy 8 s later, its drop-in is removed
#     and it is restarted unhardened (reported as ROLLED BACK). Nothing else on the system changes.
#   - the dashboard restart also activates the TLS 1.2 AEAD-only cipher list (code change in the CLI).
# Undo:  rm -r /etc/systemd/system/netsentinel-*.service.d && systemctl daemon-reload && systemctl restart 'netsentinel-*'
set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)/hardening"
healthy() {
  local u=$1
  systemctl is-active --quiet "netsentinel-$u" || return 1
  case $u in
    api)       curl -sf -m 5 http://127.0.0.1:8200/healthz >/dev/null ;;
    dashboard) curl -sfk -m 5 -o /dev/null https://127.0.0.1:8443/dashboard/login ;;
    *)         ! journalctl -u "netsentinel-$u" --since "-10s" --no-pager | grep -qE "Traceback|Error|failed" ;;
  esac
}
for u in api detection orchestrator investigation risk response ticket dashboard; do
  d=/etc/systemd/system/netsentinel-$u.service.d
  mkdir -p "$d"
  install -m 0644 "$HERE/hardening.conf" "$d/hardening.conf"
  [[ $u != investigation ]] && install -m 0644 "$HERE/python-only.conf" "$d/python-only.conf"
  systemctl daemon-reload
  systemctl restart "netsentinel-$u"; sleep 8
  if healthy "$u"; then
    printf '%-14s hardened   %s\n' "$u" "$(systemd-analyze security "netsentinel-$u" --no-pager | tail -1 | grep -oE '[0-9.]+ [A-Z]+')"
  else
    rm -f "$d/hardening.conf" "$d/python-only.conf"; systemctl daemon-reload; systemctl restart "netsentinel-$u"
    printf '%-14s ROLLED BACK (see: journalctl -u netsentinel-%s -n 30)\n' "$u" "$u"
  fi
done
# openssl exits non-zero when the handshake is refused, so capture its output rather than piping
# (with pipefail, a refused handshake would otherwise look like a failed check).
tls_out=$(echo | openssl s_client -connect 127.0.0.1:8443 -tls1_2 -cipher 'AES128-SHA:AES256-SHA:ECDHE-ECDSA-AES128-SHA' 2>&1)
[[ $tls_out == *"Cipher is (NONE)"* ]] && echo "dashboard TLS 1.2: CBC suites refused" || echo "dashboard TLS 1.2: CBC still accepted"
