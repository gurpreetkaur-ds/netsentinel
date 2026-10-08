#!/usr/bin/env bash
# Installs NetSentinel's services. Run as root:  sudo bash ~/netsentinel/ops/systemd/install.sh
#
# What it changes:
#   - copies 7 unit files into /etc/systemd/system (nothing else on the system is modified)
#   - enables + starts them: they run as linuxuser (not root), with the wall-netsentinel-clients
#     supplementary group (Security Wall access), NoNewPrivileges, a private /tmp, and a read-only
#     filesystem except ~/.claude for the Investigation Agent
#   - the API listens on 127.0.0.1:8200 only; no firewall rule is added, nothing is exposed
# Undo:  systemctl disable --now netsentinel-{api,detection,orchestrator,investigation,risk,response,ticket}
#        rm /etc/systemd/system/netsentinel-*.service && systemctl daemon-reload
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
UNITS=(api detection orchestrator investigation risk response ticket)
for u in "${UNITS[@]}"; do
  install -m 0644 -o root -g root "$HERE/netsentinel-$u.service" "/etc/systemd/system/netsentinel-$u.service"
done
systemctl daemon-reload
for u in "${UNITS[@]}"; do systemctl enable --now "netsentinel-$u.service"; done
sleep 5
for u in "${UNITS[@]}"; do printf '%-36s %s\n' "netsentinel-$u" "$(systemctl is-active "netsentinel-$u")"; done
curl -s http://127.0.0.1:8200/healthz && echo
