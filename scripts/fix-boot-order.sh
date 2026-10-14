#!/bin/bash
# Fix the reboot race that left NetSentinel without its database after the 2026-10-08 reboot:
# OpenBao started before PostgreSQL was ready, failed once, and wall-proxy@netsentinel
# gave up on it ("dependency failed") instead of waiting for OpenBao's automatic restart.
set -euo pipefail

# 1. Make OpenBao start only after PostgreSQL is up (prevents the race on future reboots).
mkdir -p /etc/systemd/system/openbao.service.d
cat > /etc/systemd/system/openbao.service.d/after-postgres.conf <<'EOF'
[Unit]
Wants=postgresql@16-main.service
After=postgresql@16-main.service
EOF
systemctl daemon-reload

# 2. Start the NetSentinel secrets proxy now (the agents reconnect on their own).
systemctl start wall-proxy@netsentinel
sleep 5
systemctl is-active wall-proxy@netsentinel
curl -s http://127.0.0.1:8200/healthz; echo
