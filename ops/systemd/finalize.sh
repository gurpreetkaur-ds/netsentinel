#!/usr/bin/env bash
# Final root step. Run as root:  sudo bash ~/netsentinel/ops/systemd/finalize.sh
#
# What it changes:
#   - adds /etc/systemd/system/netsentinel-investigation.service.d/shutdown.conf (KillMode=mixed,
#     TimeoutStopSec=200): on stop/restart the agent finishes in-flight Claude investigations
#     instead of the Claude processes being killed mid-answer
#   - restarts netsentinel-investigation once (waits for any running investigation to finish)
# Undo:  rm /etc/systemd/system/netsentinel-investigation.service.d/shutdown.conf && systemctl daemon-reload
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
install -m 0644 "$HERE/hardening/investigation-shutdown.conf" /etc/systemd/system/netsentinel-investigation.service.d/shutdown.conf
systemctl daemon-reload
systemctl restart netsentinel-investigation
sleep 5
printf 'netsentinel-investigation: %s  KillMode=%s  TimeoutStopUSec=%s\n' "$(systemctl is-active netsentinel-investigation)" \
  "$(systemctl show -p KillMode --value netsentinel-investigation)" "$(systemctl show -p TimeoutStopUSec --value netsentinel-investigation)"
