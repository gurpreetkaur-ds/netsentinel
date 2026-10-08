#!/usr/bin/env bash
# Opens the NetSentinel dashboard on https://<server>:8443 for your IP addresses only (owner_ips in config/site.json).
# Run as root:  sudo bash ~/netsentinel/ops/systemd/enable-dashboard.sh
#
# What it changes:
#   - installs + starts netsentinel-dashboard.service (runs as linuxuser, not root): HTTPS with the
#     self-signed certificate in ~/.config/netsentinel/tls, dashboard pages only (no /v1 API)
#   - adds ufw rules: TCP 8443 allowed ONLY from the IPs below; everyone else stays blocked
# Undo:  systemctl disable --now netsentinel-dashboard && rm /etc/systemd/system/netsentinel-dashboard.service
#        ufw delete allow from <ip> to any port 8443 proto tcp   (for each IP)
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
CFG="$(cd "$(dirname "$0")/../.." && pwd)/config/site.json"   # domain / IPs: local, never committed
[[ -r "$CFG" ]] || { echo "missing $CFG (copy config/site.example.json and fill it in)" >&2; exit 1; }
mapfile -t ALLOW_FROM < <(jq -r '.owner_ips[]' "$CFG")
HERE="$(cd "$(dirname "$0")" && pwd)"
install -m 0644 -o root -g root "$HERE/netsentinel-dashboard.service" /etc/systemd/system/netsentinel-dashboard.service
systemctl daemon-reload
systemctl enable --now netsentinel-dashboard.service
for ip in "${ALLOW_FROM[@]}"; do
  ufw allow from "$ip" to any port 8443 proto tcp comment "NetSentinel dashboard (HTTPS)"
done
sleep 3
printf 'netsentinel-dashboard: %s\n' "$(systemctl is-active netsentinel-dashboard)"
ufw status | grep 8443
curl -sk -o /dev/null -w 'local check https://127.0.0.1:8443/dashboard/login -> %{http_code}\n' https://127.0.0.1:8443/dashboard/login
