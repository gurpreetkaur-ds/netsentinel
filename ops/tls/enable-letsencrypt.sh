#!/usr/bin/env bash
# Trusted HTTPS for the NetSentinel dashboard: https://<domain>:8443/dashboard (domain in config/site.json)
# Run as root:  sudo bash ~/netsentinel/ops/tls/enable-letsencrypt.sh
#
# What it changes:
#   1. apt installs certbot (its package also installs a systemd timer that renews certificates)
#   2. proves domain ownership to Let's Encrypt by placing a one-time file under Apache's existing
#      web root (/var/www/html/public/.well-known/acme-challenge/); Apache and its config are unchanged
#   3. registers anonymously (no e-mail is sent to Let's Encrypt)
#   4. adds a deploy hook that copies the certificate to ~linuxuser/.config/netsentinel/tls/
#      (key mode 600, owned by linuxuser) and restarts netsentinel-dashboard, on issue and every renewal
# No firewall change: port 80 is already public; 8443 stays limited to your IPs.
# Undo:  certbot delete --cert-name <domain>
#        rm /etc/letsencrypt/renewal-hooks/deploy/netsentinel-dashboard.sh   (the old self-signed cert can be regenerated)
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
CFG="$(cd "$(dirname "$0")/../.." && pwd)/config/site.json"   # domain / IPs: local, never committed
[[ -r "$CFG" ]] || { echo "missing $CFG (copy config/site.example.json and fill it in)" >&2; exit 1; }
DOMAIN="$(jq -r .domain "$CFG")"
WEBROOT=/var/www/html/public
HOOK=/etc/letsencrypt/renewal-hooks/deploy/netsentinel-dashboard.sh

command -v certbot >/dev/null || { apt-get update -qq && apt-get install -y -qq certbot; }

certbot certonly --webroot -w "$WEBROOT" -d "$DOMAIN" --agree-tos --register-unsafely-without-email \
    --non-interactive --keep-until-expiring

mkdir -p "$(dirname "$HOOK")"
cat > "$HOOK" <<HOOKEOF
#!/usr/bin/env bash
# Installed by NetSentinel: hand the renewed certificate to the dashboard service.
set -euo pipefail
[[ "\${RENEWED_DOMAINS:-$DOMAIN}" == *"$DOMAIN"* ]] || exit 0
DEST=/home/linuxuser/.config/netsentinel/tls
install -m 644 -o linuxuser -g linuxuser /etc/letsencrypt/live/$DOMAIN/fullchain.pem "\$DEST/cert.pem"
install -m 600 -o linuxuser -g linuxuser /etc/letsencrypt/live/$DOMAIN/privkey.pem "\$DEST/key.pem"
systemctl restart netsentinel-dashboard
HOOKEOF
chmod 750 "$HOOK"
RENEWED_DOMAINS="$DOMAIN" bash "$HOOK"

sleep 3
systemctl list-timers certbot.timer --no-pager | head -3
echo | openssl s_client -connect 127.0.0.1:8443 -servername "$DOMAIN" 2>/dev/null | openssl x509 -noout -issuer -subject -enddate
curl -s -o /dev/null -w "https://$DOMAIN:8443/dashboard/login -> %{http_code} (verified TLS)\n" "https://$DOMAIN:8443/dashboard/login"
