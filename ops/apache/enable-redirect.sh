#!/usr/bin/env bash
# Sends http://<domain> to the secure dashboard and enables HSTS (domain in config/site.json).
# Run as root:  sudo bash ~/netsentinel/ops/apache/enable-redirect.sh
#
# What it changes:
#   - adds Apache site "netsentinel" (only for that host name):
#     every plain-HTTP request -> 301 to https://<domain>:8443/dashboard,
#     except /.well-known/acme-challenge/ (certificate renewals). Your default Apache site is untouched.
#   - checks the Apache config before reloading (a bad config aborts with nothing changed)
#   - restarts netsentinel-dashboard so it starts sending the HSTS header
# Undo:  a2dissite netsentinel && systemctl reload apache2 && rm /etc/apache2/sites-available/netsentinel.conf
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
CFG="$(cd "$(dirname "$0")/../.." && pwd)/config/site.json"   # domain / IPs: local, never committed
[[ -r "$CFG" ]] || { echo "missing $CFG (copy config/site.example.json and fill it in)" >&2; exit 1; }
DOMAIN="$(jq -r .domain "$CFG")"
sed "s/__DOMAIN__/$DOMAIN/g" "$HERE/netsentinel.conf" > /etc/apache2/sites-available/netsentinel.conf
chmod 0644 /etc/apache2/sites-available/netsentinel.conf
a2ensite -q netsentinel
if ! apache2ctl configtest; then
  a2dissite -q netsentinel; rm -f /etc/apache2/sites-available/netsentinel.conf
  echo "Apache config test failed; change reverted" >&2; exit 1
fi
systemctl reload apache2
systemctl restart netsentinel-dashboard
sleep 3
curl -s -o /dev/null -w "http://$DOMAIN/ -> %{http_code} -> %{redirect_url}\n" "http://$DOMAIN/"
curl -s -o /dev/null -w "http://<server ip>/ (your other site) -> %{http_code}\n" http://127.0.0.1/
curl -sI "https://$DOMAIN:8443/dashboard/login" | grep -i strict-transport-security
