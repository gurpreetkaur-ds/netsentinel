#!/usr/bin/env bash
# Opens a short OpenBao operator window (unauthenticated generate-root on the local unix socket
# only), runs the NetSentinel onboarding, then ALWAYS restores the original config and verifies it.
# Run as root:  sudo bash ~/netsentinel/ops/wall/maintenance-window.sh
set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
HCL=/etc/openbao/openbao.hcl
BAK="$HCL.bak-netsentinel-$(date +%Y%m%d%H%M%S)"
export BAO_ADDR=unix:///run/openbao/bao.sock
unsealed() { for _ in $(seq 1 60); do [[ "$(bao status -format=json 2>/dev/null | jq -r .sealed)" == false ]] && return 0; sleep 1; done; return 1; }
restore() {
  cp -p "$BAK" "$HCL" && systemctl restart openbao && unsealed && echo ">>> window CLOSED: original config restored, OpenBao unsealed"
  cmp -s "$BAK" "$HCL" && echo ">>> config identical to backup" || echo ">>> WARNING: config differs from backup $BAK"
}
bash -n /home/linuxuser/netsentinel/ops/wall/onboard-netsentinel.sh || exit 1
cp -p "$HCL" "$BAK" && echo ">>> backup: $BAK"
trap restore EXIT
sed -i '0,/^listener "unix" {/s//listener "unix" {\n  disable_unauthed_generate_root_endpoints = false/' "$HCL"
systemctl restart openbao && unsealed && echo ">>> window OPEN (OpenBao unsealed)"
bash /home/linuxuser/netsentinel/ops/wall/onboard-netsentinel.sh --yes
echo ">>> onboarding exit code: $?"
