#!/usr/bin/env bash
# SOC console upgrade (migration 0010 + new code). Run as root:
#   sudo bash ~/netsentinel/ops/deploy/soc-upgrade.sh
#
# What it changes:
#   1. backs up the netsentinel database to /var/backups/netsentinel/pre-0010-<time>.sql.gz (root only)
#   2. applies migration 0010_soc_workflow as linuxuser through the Security Wall (adds tables/columns;
#      renames ticket status 'new' to 'open'; nothing is deleted)
#   3. restarts the NetSentinel API, dashboard and agents so they run the new code. The Investigation
#      Agent finishes in-flight investigations first and now also runs the AI Security Agent worker.
#   4. checks the API, the dashboard and the AI worker's heartbeat
# No unit files, firewall rules or permissions change.
#
# Undo: stop the services, restore the backup
#   (gunzip -c BACKUP | sudo -u postgres psql -v ON_ERROR_STOP=1 -d netsentinel_restore …), check out the
#   previous code (git -C ~linuxuser/netsentinel checkout <commit>), and start the services again.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
REPO=/home/linuxuser/netsentinel
STAMP=$(date -u +%Y%m%dT%H%M%SZ)

echo "== 1/4 backup"
install -d -m 0700 /var/backups/netsentinel
sudo -u postgres pg_dump --no-owner netsentinel | gzip > "/var/backups/netsentinel/pre-0010-$STAMP.sql.gz"
chmod 600 "/var/backups/netsentinel/pre-0010-$STAMP.sql.gz"
ls -lh "/var/backups/netsentinel/pre-0010-$STAMP.sql.gz"

echo "== 2/4 migrate"
sudo -u linuxuser -g wall-netsentinel-clients bash -c "cd $REPO && .venv/bin/netsentinel migrate"

echo "== 3/4 restart services"
systemctl restart netsentinel-api netsentinel-dashboard netsentinel-ticket netsentinel-response \
                  netsentinel-risk netsentinel-orchestrator netsentinel-detection
systemctl restart netsentinel-investigation     # waits for in-flight Claude investigations (KillMode=mixed)

echo "== 4/4 verify"
sleep 8
for u in api dashboard detection orchestrator investigation risk response ticket; do
  printf '%-28s %s\n' "netsentinel-$u" "$(systemctl is-active netsentinel-$u)"
done
printf 'API health:        %s\n' "$(curl -s http://127.0.0.1:8200/healthz)"
printf 'Dashboard login:   HTTP %s\n' "$(curl -sk -o /dev/null -w '%{http_code}' \
  https://127.0.0.1:8443/dashboard/login)"
for i in $(seq 1 12); do
  hb=$(sudo -u postgres psql -d netsentinel -tAc "SELECT status FROM agent_heartbeats WHERE agent = 'assistant' AND at > now() - interval '2 minutes'" 2>/dev/null || true)
  [[ -n "$hb" ]] && { echo "AI agent worker:   $hb"; break; }
  sleep 5
done
[[ -n "${hb:-}" ]] || echo "AI agent worker:   no heartbeat yet (check: journalctl -u netsentinel-investigation -n 50)"
echo "done"
