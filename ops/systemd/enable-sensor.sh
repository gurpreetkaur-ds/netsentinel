#!/usr/bin/env bash
# Starts the NetSentinel live sensor. Run as root:  sudo bash ~/netsentinel/ops/systemd/enable-sensor.sh
#
# What it changes:
#   - installs + starts netsentinel-sensor.service. It runs as linuxuser with ONE extra privilege,
#     CAP_NET_RAW (open a raw packet socket), plus the usual sandbox; it is not root.
#   - it reads packet headers on enp1s0 (this server's own traffic, no promiscuous mode) and turns them
#     into flow metadata: addresses, ports, sizes, timings, TCP flags. Packet contents are never stored or sent.
#   - flows go to the local NetSentinel API (127.0.0.1:8200) with an in-memory, ingest-only API key that
#     expires after 24 h and is revoked when the sensor stops. No firewall change.
# Undo:  systemctl disable --now netsentinel-sensor && rm /etc/systemd/system/netsentinel-sensor.service
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
install -m 0644 -o root -g root "$HERE/netsentinel-sensor.service" /etc/systemd/system/netsentinel-sensor.service
systemctl daemon-reload
systemctl enable --now netsentinel-sensor.service
sleep 75
printf 'netsentinel-sensor: %s\n' "$(systemctl is-active netsentinel-sensor)"
journalctl -u netsentinel-sensor --since "-2 min" --no-pager -o cat | grep -E "capturing|sent [0-9]+ flows|ERROR|Traceback" | tail -3
