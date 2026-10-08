#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────────────────
# Onboard NetSentinel onto the Security Wall (OpenBao), mirroring the Resumate setup.
#
#   Review first, then run as root:   sudo bash ops/wall/onboard-netsentinel.sh
#   Non-interactive (after review):    sudo bash ops/wall/onboard-netsentinel.sh --yes
#
# The script pauses for confirmation before each phase and is safe to re-run (idempotent).
# It never prints a secret: the DB password is generated inside PostgreSQL and immediately
# replaced by OpenBao; the unseal key is piped from its encrypted store straight into OpenBao;
# the temporary root token lives only in this shell's memory and is revoked on exit.
#
# Phases
#   1. PostgreSQL  – least-privilege login role `netsentinel_app`, databases, rotation grant
#   2. OpenBao     – short-lived root token (needed: wall-admin cannot create policies/AppRoles)
#   3. OpenBao     – policy `netsentinel`, AppRole `netsentinel` (copied from resumate's
#                    settings), DB static role `netsentinel-db` (24h auto-rotation)
#   4. System      – proxy OS identity, socket group, proxy config, wallctl entry, systemd unit
# ─────────────────────────────────────────────────────────────────────────────────────────
set -euo pipefail
umask 077

PROJECT=netsentinel
PG_ROLE=netsentinel_app
DATABASES=(netsentinel netsentinel_test)
STATIC_ROLE=netsentinel-db
TEMPLATE=resumate                       # existing project whose wall settings we copy
APP_USER=linuxuser                      # OS user that runs NetSentinel
UNSEAL_CRED=/etc/credstore.encrypted/openbao-unseal.cred
WALLCTL=/usr/local/sbin/wallctl
export BAO_ADDR=unix:///run/openbao/bao.sock
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[[ $EUID -eq 0 ]] || { echo "Run as root: sudo bash $0" >&2; exit 1; }
for bin in bao jq psql systemd-creds; do command -v "$bin" >/dev/null || { echo "missing: $bin" >&2; exit 1; }; done

step()    { printf '\n\033[1m==== %s ====\033[0m\n' "$*"; }
ASSUME_YES=0; [[ "${1:-}" == "--yes" ]] && ASSUME_YES=1
confirm() {
  if (( ASSUME_YES )); then echo "$1 [--yes: proceeding]"; return; fi
  read -r -p "$1 [y/N] " a; [[ $a == [yY] ]] || { echo "Stopped. Nothing further was changed."; exit 1; }
}
psql_pg() { sudo -u postgres psql -v ON_ERROR_STOP=1 -qAt "$@"; }

# ── Phase 1: PostgreSQL ──────────────────────────────────────────────────────────────────
step "1/4 PostgreSQL: role '$PG_ROLE', databases ${DATABASES[*]}, rotation grant to 'openbao'"
cat <<EOF
Will (only if missing):
  - CREATE ROLE $PG_ROLE LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE (random password, never shown;
    OpenBao replaces it in phase 3)
  - CREATE DATABASE ${DATABASES[*]} OWNER $PG_ROLE, and REVOKE CONNECT FROM PUBLIC on them
  - GRANT $PG_ROLE TO openbao WITH ADMIN OPTION   (lets OpenBao rotate this role's password —
    same grant resume_app and laravel_user already have; it gives OpenBao no other access)
EOF
confirm "Apply phase 1?"
psql_pg <<SQL
DO \$\$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '$PG_ROLE') THEN
    EXECUTE format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD %L',
                   '$PG_ROLE', gen_random_uuid()::text || gen_random_uuid()::text);
  END IF;
END \$\$;
GRANT $PG_ROLE TO openbao WITH ADMIN OPTION;
SQL
for db in "${DATABASES[@]}"; do
  psql_pg -c "SELECT 1 FROM pg_database WHERE datname = '$db'" | grep -q 1 \
    || psql_pg -c "CREATE DATABASE $db OWNER $PG_ROLE"
  psql_pg -c "REVOKE CONNECT ON DATABASE $db FROM PUBLIC; GRANT CONNECT ON DATABASE $db TO $PG_ROLE;"
done
psql_pg -c "SELECT rolname, rolsuper, rolcreatedb, rolcreaterole FROM pg_roles WHERE rolname = '$PG_ROLE'"
echo "phase 1 done"

# ── Phase 2: temporary OpenBao root token ────────────────────────────────────────────────
step "2/4 OpenBao: temporary root token"
cat <<EOF
Why root: the wall-admin identity used by 'wallctl' is intentionally unable to create policies,
AppRoles or change database connections. A root token is generated from the unseal key
(decrypted by systemd-creds and piped directly into OpenBao, never displayed), kept only in this
shell's memory, and revoked when the script exits — even on error. Every call is audit-logged.
EOF
confirm "Generate the temporary root token?"
# OpenBao 2.7's CLI targets the authenticated sys/generate-root-token endpoint; the unseal-key flow
# uses the classic sys/generate-root endpoint (enabled only while the operator's window is open).
api_root() { curl -sf --unix-socket /run/openbao/bao.sock -X "$1" "http://localhost/v1/sys/generate-root/$2" "${@:3}"; }
api_root DELETE attempt >/dev/null 2>&1 || true
INIT="$(api_root PUT attempt -d '{}')" || { echo "classic generate-root endpoint unavailable (is the operator window open?)" >&2; exit 1; }
NONCE="$(jq -r .nonce <<<"$INIT")"; OTP="$(jq -r .otp <<<"$INIT")"
[[ -n "$OTP" && "$OTP" != null ]] || { echo "server did not return an OTP" >&2; exit 1; }
cleanup() {
  if [[ -n "${BAO_TOKEN:-}" ]]; then bao token revoke -self >/dev/null 2>&1 && echo "temporary root token revoked"; fi
  api_root DELETE attempt >/dev/null 2>&1 || true
  unset BAO_TOKEN OTP NONCE ENCODED INIT
}
trap cleanup EXIT
ENCODED="$(systemd-creds decrypt --name=unseal "$UNSEAL_CRED" - \
  | jq -Rs --arg n "$NONCE" '{key: rtrimstr("\n"), nonce: $n}' \
  | api_root PUT update -d @- | jq -r '.encoded_token // .encoded_root_token')"
[[ -n "$ENCODED" && "$ENCODED" != null ]] || { echo "root token generation did not complete" >&2; exit 1; }
# The 2.7 CLI's -decode also queries the blocked status endpoint, so decode locally:
# token = base64(encoded) XOR otp.
BAO_TOKEN="$(ENC="$ENCODED" OTP="$OTP" python3 -c '
import base64, os
e = os.environ["ENC"].rstrip("="); o = os.environ["OTP"].encode()
b = base64.b64decode(e + "=" * (-len(e) % 4))
print(bytes(x ^ y for x, y in zip(b, o)).decode())')"
export BAO_TOKEN
bao token lookup -format=json | jq -e '.data.policies | index("root")' >/dev/null \
  || { echo "decoded token is not a valid root token" >&2; exit 1; }
echo "temporary root token obtained (TTL-less root; revoked at exit)"

# Revoke orphaned root tokens left by earlier interrupted runs (their OTPs are lost, so they are
# unusable, but they should not linger).
SELF_ACC="$(bao token lookup -format=json | jq -r .data.accessor)"
for acc in $(bao list -format=json auth/token/accessors | jq -r '.[]'); do
  [[ "$acc" == "$SELF_ACC" ]] && continue
  if bao write -format=json auth/token/lookup-accessor accessor="$acc" | jq -e '.data.policies | index("root")' >/dev/null; then
    bao write auth/token/revoke-accessor accessor="$acc" >/dev/null && echo "revoked orphaned root token (accessor ${acc:0:8}…)"
  fi
done

# ── Phase 3: policy, AppRole, DB static role ─────────────────────────────────────────────
step "3/4 OpenBao: policy, AppRole and DB static role"
TEMPLATE_ROLE="$(bao read -format=json "auth/approle/role/$TEMPLATE" | jq '.data')"
CONN="$(bao read -format=json "database/static-roles/$TEMPLATE-db" | jq -r '.data.db_name')"
ROTATION="$(bao read -format=json "database/static-roles/$TEMPLATE-db" | jq -r '.data.rotation_period')"
CONN_CFG="$(bao read -format=json "database/config/$CONN" | jq '.data')"
ALLOWED="$(jq -c '.allowed_roles // []' <<<"$CONN_CFG")"

echo "Policy to install ($HERE/$PROJECT.hcl):"; sed 's/^/    /' "$HERE/$PROJECT.hcl"
echo "AppRole '$PROJECT' will copy these settings from '$TEMPLATE' (token_policies -> [$PROJECT]):"
jq 'del(.policies, .token_policies)' <<<"$TEMPLATE_ROLE" | sed 's/^/    /'
echo "DB connection '$CONN' (plugin $(jq -r .plugin_name <<<"$CONN_CFG")): allowed_roles now $ALLOWED -> adds '$STATIC_ROLE'"
echo "Static role '$STATIC_ROLE': username=$PG_ROLE rotation_period=${ROTATION}s (same as $TEMPLATE)"
confirm "Apply phase 3?"

bao policy write "$PROJECT" "$HERE/$PROJECT.hcl"
install -m 0644 -o root -g root "$HERE/$PROJECT.hcl" "/etc/wall/policies/$PROJECT.hcl"

jq --arg p "$PROJECT" 'del(.policies) | .token_policies = [$p]' <<<"$TEMPLATE_ROLE" \
  | bao write "auth/approle/role/$PROJECT" - >/dev/null
echo "AppRole '$PROJECT' written"

if ! jq -e --arg r "$STATIC_ROLE" 'index("*") != null or index($r) != null' <<<"$ALLOWED" >/dev/null; then
  NEW_ALLOWED="$(jq -r --arg r "$STATIC_ROLE" '. + [$r] | join(",")' <<<"$ALLOWED")"
  # Update of an existing connection keeps its URL, plugin and stored credentials unchanged.
  bao write "database/config/$CONN" allowed_roles="$NEW_ALLOWED" >/dev/null
fi
echo "connection after update:"; bao read -format=json "database/config/$CONN" \
  | jq '.data | {plugin_name, allowed_roles, connection_url: .connection_details.connection_url}' | sed 's/^/    /'

bao write "database/static-roles/$STATIC_ROLE" db_name="$CONN" username="$PG_ROLE" \
  rotation_period="$ROTATION" >/dev/null
# Show rotation metadata only — the password field is deliberately filtered out.
bao read -format=json "database/static-roles/$STATIC_ROLE" \
  | jq '.data | {username, rotation_period, last_vault_rotation}' | sed 's/^/    /'
echo "phase 3 done (the initial DB password has already been replaced by OpenBao)"
cleanup; trap - EXIT

# ── Phase 4: system identity, proxy, wallctl ─────────────────────────────────────────────
step "4/4 System: proxy user/groups, proxy config, wallctl entry, systemd"
cat <<EOF
Will (only if missing):
  - system group 'wall-$PROJECT', group 'wall-$PROJECT-clients', user 'wall-$PROJECT' (nologin)
  - add 'wall-$PROJECT' to groups 'wall-$PROJECT-clients' and 'openbao' (reach bao.sock)
  - add '$APP_USER' to 'wall-$PROJECT-clients' (may use the NetSentinel proxy socket only)
  - /etc/wall/proxy-$PROJECT.hcl  (copy of proxy-$TEMPLATE.hcl with the name replaced)
  - wallctl: add "$PROJECT": "$STATIC_ROLE" to PROJECTS (+ restart hint); backup kept as wallctl.bak-<date>
  - systemctl enable wall-proxy@$PROJECT, then 'wallctl rotate-login $PROJECT' issues its login and starts it
EOF
confirm "Apply phase 4?"
getent group "wall-$PROJECT"          >/dev/null || groupadd --system "wall-$PROJECT"
getent group "wall-$PROJECT-clients"  >/dev/null || groupadd --system "wall-$PROJECT-clients"
id "wall-$PROJECT" >/dev/null 2>&1 || useradd --system --gid "wall-$PROJECT" --no-create-home \
  --home-dir /nonexistent --shell /usr/sbin/nologin "wall-$PROJECT"
usermod -aG "wall-$PROJECT-clients,openbao" "wall-$PROJECT"
usermod -aG "wall-$PROJECT-clients" "$APP_USER"

sed "s/$TEMPLATE/$PROJECT/g" "/etc/wall/proxy-$TEMPLATE.hcl" > "/etc/wall/proxy-$PROJECT.hcl"
chmod 0644 "/etc/wall/proxy-$PROJECT.hcl"

if ! grep -q "\"$PROJECT\": \"$STATIC_ROLE\"" "$WALLCTL"; then
  cp -p "$WALLCTL" "$WALLCTL.bak-$(date +%Y%m%d%H%M%S)"
  python3 - "$WALLCTL" "$PROJECT" "$STATIC_ROLE" <<'PY'
import re, sys
path, project, role = sys.argv[1:]
src = open(path).read()
src, n = re.subn(r'^(PROJECTS = \{.*)\}$', lambda m: f'{m.group(1)}, "{project}": "{role}"}}', src, count=1, flags=re.M)
assert n == 1, "PROJECTS line not found"
src = src.replace('    return "sudo systemctl restart resumate" if project == "resumate" else',
                  f'    if project == "{project}":\n        return "sudo systemctl restart {project}"\n'
                  '    return "sudo systemctl restart resumate" if project == "resumate" else', 1)
open(path, "w").write(src)
PY
  python3 -m py_compile "$WALLCTL" && echo "wallctl updated"
fi

systemctl daemon-reload
systemctl enable "wall-proxy@$PROJECT" >/dev/null 2>&1
"$WALLCTL" rotate-login "$PROJECT"
sleep 3
systemctl is-active "wall-proxy@$PROJECT"
ls -l "/run/wall-$PROJECT/proxy.sock"
"$WALLCTL" status | sed -n "/\[$PROJECT\]/,/active/p"
echo
echo "Done. '$APP_USER' must start a new login session (or the NetSentinel systemd service"
echo "must declare SupplementaryGroups=wall-$PROJECT-clients) before it can use the socket."
