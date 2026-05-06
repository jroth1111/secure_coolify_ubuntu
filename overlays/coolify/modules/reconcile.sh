#!/usr/bin/env bash
# overlays/coolify/modules/reconcile.sh — Coolify state/DB/PUSHER reconcile heredoc generators.
# Sourced by coolify-common.sh; do not execute directly.

[[ "${BASH_SOURCE[0]}" != "${0}" ]] \
  || { printf 'Source this file, do not execute it.\n' >&2; exit 1; }

# coolify_mark_bind_dashboard_state_script — Emit host-side script that updates
# server-hardening state after phase-4 dashboard binding is enforced.
coolify_mark_bind_dashboard_state_script() {
  cat <<'EOF'
set -Eeuo pipefail
state_file="/var/lib/server-hardening/state"
state_lock_file="${state_file}.lock"
tmp="$(mktemp)"

if [[ ! -f "${state_file}" ]]; then
  rm -f "${tmp}"
  exit 0
fi

if command -v flock >/dev/null 2>&1; then
  exec 9>"${state_lock_file}"
  flock 9
fi

awk '
  BEGIN { seen=0 }
  /^bind_dashboard_to_tailscale=/ {
    print "bind_dashboard_to_tailscale=true"
    seen=1
    next
  }
  { print }
  END {
    if (seen == 0) {
      print "bind_dashboard_to_tailscale=true"
    }
  }
' "${state_file}" > "${tmp}"

install -m 0640 "${tmp}" "${state_file}"
rm -f "${tmp}"

if command -v flock >/dev/null 2>&1; then
  flock -u 9 || true
  exec 9>&-
fi
EOF
}

# coolify_install_binding_guard_script — Emit host-side script that installs and
# enables the Coolify UFW binding guard timer after phase-4 binding is configured.
coolify_install_binding_guard_script() {
  cat <<'EOF'
set -Eeuo pipefail
guard_script="/usr/local/sbin/coolify-binding-guard.sh"
guard_service="/etc/systemd/system/coolify-binding-guard.service"
guard_timer="/etc/systemd/system/coolify-binding-guard.timer"

install -d -m 0755 /usr/local/sbin

cat > "${guard_script}" <<'GUARD_EOF'
#!/usr/bin/env bash
set -Euo pipefail

TAILSCALE_IFACE="tailscale0"
LOG_TAG="coolify-binding-guard"

log() { logger -t "${LOG_TAG}" -- "$*"; }

delete_non_tailscale_rule_numbers() {
  local numbered rules=()
  numbered="$(ufw status numbered 2>/dev/null || true)"
  mapfile -t rules < <(
    awk '
      BEGIN { IGNORECASE=1 }
      /\[[[:space:]]*[0-9]+\]/ && /ALLOW IN/ && /(8000|6001|6002)(\/tcp)?/ {
        line=tolower($0)
        if (index(line, "tailscale0") == 0) {
          rule=$1
          gsub(/\[/, "", rule)
          gsub(/\]/, "", rule)
          print rule
        }
      }
    ' <<< "${numbered}" | sort -rn
  )
  printf '%s\n' "${rules[@]}"
}

command -v ufw >/dev/null 2>&1 || { log "ufw not found; skipping."; exit 0; }
ufw_status="$(ufw status 2>/dev/null | head -1)" || true
[[ "${ufw_status}" == "Status: active" ]] || { log "UFW not active; skipping."; exit 0; }

changed=false
while IFS= read -r rule_number; do
  [[ -n "${rule_number}" ]] || continue
  ufw --force delete "${rule_number}" >/dev/null 2>&1 || true
  changed=true
done < <(delete_non_tailscale_rule_numbers)
if ! ufw status | grep -q "8000.*on ${TAILSCALE_IFACE}"; then
  ufw allow in on "${TAILSCALE_IFACE}" proto tcp to any port 8000 comment "coolify-hardening-dashboard-tailscale" >/dev/null 2>&1 || true
  changed=true
fi
if ! ufw status | grep -q "6001.*on ${TAILSCALE_IFACE}"; then
  ufw allow in on "${TAILSCALE_IFACE}" proto tcp to any port 6001 comment "coolify-hardening-soketi-tailscale" >/dev/null 2>&1 || true
  changed=true
fi
if ! ufw status | grep -q "6002.*on ${TAILSCALE_IFACE}"; then
  ufw allow in on "${TAILSCALE_IFACE}" proto tcp to any port 6002 comment "coolify-hardening-terminal-tailscale" >/dev/null 2>&1 || true
  changed=true
fi

if "${changed}"; then
  log "UFW binding rules repaired on ${TAILSCALE_IFACE}."
fi
GUARD_EOF
chmod 0750 "${guard_script}"

cat > "${guard_service}" <<'UNIT_EOF'
[Unit]
Description=Verify Coolify dashboard UFW rules on tailscale0 are present
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/coolify-binding-guard.sh
UNIT_EOF

cat > "${guard_timer}" <<'TIMER_EOF'
[Unit]
Description=Periodically verify Coolify dashboard UFW rules on tailscale0

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=30s

[Install]
WantedBy=timers.target
TIMER_EOF

systemctl daemon-reload
systemctl enable --now coolify-binding-guard.timer
systemctl start coolify-binding-guard.service || true
EOF
}

# coolify_set_wildcard_domain_script — Emit host-side script to update Coolify
# wildcard domain directly in PostgreSQL. Requires APP_DOMAIN in environment.
coolify_set_wildcard_domain_script() {
  cat <<'EOF'
set -Eeuo pipefail
: "${APP_DOMAIN:?APP_DOMAIN is required}"
coolify_env="/data/coolify/source/.env"
db_user="$(grep -m1 '^DB_USERNAME=' "${coolify_env}" | cut -d= -f2- || true)"
db_name="$(grep -m1 '^DB_DATABASE=' "${coolify_env}" | cut -d= -f2- || true)"
db_pass="$(grep -m1 '^DB_PASSWORD=' "${coolify_env}" | cut -d= -f2- || true)"
db_user="${db_user:-coolify}"
db_name="${db_name:-coolify}"
[[ -n "${db_pass}" ]] || { echo "DB_PASSWORD missing in ${coolify_env}" >&2; exit 1; }
if ! docker ps --filter "name=coolify-db" --filter "status=running" --format "{{.Names}}" 2>/dev/null | grep -qx "coolify-db"; then
  echo "coolify-db container is not running" >&2
  exit 1
fi
wait_for_coolify_postgres() {
  local attempts="${1:-30}" delay="${2:-2}" attempt
  for (( attempt=1; attempt<=attempts; attempt++ )); do
    if docker exec -i coolify-db sh -ceu '
      IFS= read -r PGPASSWORD
      export PGPASSWORD
      pg_isready -U "$1" -d "$2" >/dev/null 2>&1
    ' _ "${db_user}" "${db_name}" <<< "${db_pass}"; then
      return 0
    fi
    (( attempt < attempts )) || break
    sleep "${delay}"
  done
  echo "coolify-db is running but PostgreSQL is not ready yet" >&2
  exit 1
}
wait_for_coolify_postgres
sql="$(cat <<SQL
DO \$\$
DECLARE
  targeted_rows integer;
  total_rows integer;
BEGIN
  SELECT COUNT(*) INTO targeted_rows FROM server_settings WHERE server_id = 0;
  IF targeted_rows = 1 THEN
    UPDATE server_settings
       SET wildcard_domain = 'http://${APP_DOMAIN}'
     WHERE server_id = 0;
    RETURN;
  END IF;

  SELECT COUNT(*) INTO total_rows FROM server_settings;
  IF targeted_rows = 0 AND total_rows = 1 THEN
    UPDATE server_settings
       SET wildcard_domain = 'http://${APP_DOMAIN}';
    RETURN;
  END IF;

  RAISE EXCEPTION 'Unable to identify a unique Coolify server_settings row (server_id=0 rows=%, total rows=%).',
    targeted_rows, total_rows;
END
\$\$;
SQL
)"
docker exec -i coolify-db sh -ceu '
  IFS= read -r PGPASSWORD
  export PGPASSWORD
  psql -v ON_ERROR_STOP=1 -U "$1" -d "$2" -c "$3" >/dev/null
' _ "${db_user}" "${db_name}" "${sql}" <<< "${db_pass}"
EOF
}

# coolify_reconcile_instance_settings_script — Emit host-side script to update
# Coolify instance settings directly in PostgreSQL. Requires DOMAIN and
# DEPLOY_MODE. Tunnel mode keeps fqdn empty so Coolify does not regenerate
# conflicting dashboard HTTPS routers; standard mode sets fqdn to the public
# dashboard URL.
coolify_reconcile_instance_settings_script() {
  cat <<'EOF'
set -Eeuo pipefail
: "${DOMAIN:?DOMAIN is required}"
: "${DEPLOY_MODE:?DEPLOY_MODE is required}"
coolify_env="/data/coolify/source/.env"
db_user="$(grep -m1 '^DB_USERNAME=' "${coolify_env}" | cut -d= -f2- || true)"
db_name="$(grep -m1 '^DB_DATABASE=' "${coolify_env}" | cut -d= -f2- || true)"
db_pass="$(grep -m1 '^DB_PASSWORD=' "${coolify_env}" | cut -d= -f2- || true)"
db_user="${db_user:-coolify}"
db_name="${db_name:-coolify}"
[[ -n "${db_pass}" ]] || { echo "DB_PASSWORD missing in ${coolify_env}" >&2; exit 1; }
if ! docker ps --filter "name=coolify-db" --filter "status=running" --format "{{.Names}}" 2>/dev/null | grep -qx "coolify-db"; then
  echo "coolify-db container is not running" >&2
  exit 1
fi
wait_for_coolify_postgres() {
  local attempts="${1:-30}" delay="${2:-2}" attempt
  for (( attempt=1; attempt<=attempts; attempt++ )); do
    if docker exec -i coolify-db sh -ceu '
      IFS= read -r PGPASSWORD
      export PGPASSWORD
      pg_isready -U "$1" -d "$2" >/dev/null 2>&1
    ' _ "${db_user}" "${db_name}" <<< "${db_pass}"; then
      return 0
    fi
    (( attempt < attempts )) || break
    sleep "${delay}"
  done
  echo "coolify-db is running but PostgreSQL is not ready yet" >&2
  exit 1
}
wait_for_coolify_postgres
sql_fqdn=""
if [[ "${DEPLOY_MODE}" == "tunnel" ]]; then
  sql_fqdn=""
else
  sql_fqdn="https://${DOMAIN}"
fi
sql="$(cat <<SQL
DO \$\$
DECLARE
  total_rows integer;
BEGIN
  SELECT COUNT(*) INTO total_rows FROM instance_settings;
  IF total_rows != 1 THEN
    RAISE EXCEPTION 'Expected exactly one instance_settings row, found %.', total_rows;
  END IF;

  UPDATE instance_settings
     SET is_registration_enabled = false,
         fqdn = '${sql_fqdn}'
   WHERE id = (SELECT id FROM instance_settings ORDER BY id LIMIT 1);
END
\$\$;
SQL
)"
docker exec -i coolify-db sh -ceu '
  IFS= read -r PGPASSWORD
  export PGPASSWORD
  psql -v ON_ERROR_STOP=1 -U "$1" -d "$2" -c "$3" >/dev/null
' _ "${db_user}" "${db_name}" "${sql}" <<< "${db_pass}"
EOF
}

# coolify_reconcile_pusher_env_script — Emit host-side script to reconcile
# PUSHER_* environment variables by deployment mode.
# Tunnel mode requires DEPLOY_MODE=tunnel and DOMAIN.
coolify_reconcile_pusher_env_script() {
  cat <<'EOF'
set -Eeuo pipefail
: "${DEPLOY_MODE:?DEPLOY_MODE is required}"
coolify_env="/data/coolify/source/.env"
mode="${DEPLOY_MODE}"
tmp="$(mktemp)"
sed '/^PUSHER_HOST=/d; /^PUSHER_PORT=/d; /^PUSHER_SCHEME=/d' "${coolify_env}" > "${tmp}"

if [[ "${mode}" == "tunnel" ]]; then
  : "${DOMAIN:?DOMAIN is required for tunnel mode}"
  cat >> "${tmp}" <<INNER
PUSHER_HOST=ws.${DOMAIN}
PUSHER_PORT=443
PUSHER_SCHEME=https
INNER
fi

if cmp -s "${tmp}" "${coolify_env}"; then
  rm -f "${tmp}"
  echo "PUSHER env unchanged for mode=${mode}"
  exit 0
fi

install -m 0600 "${tmp}" "${coolify_env}"
rm -f "${tmp}"
echo "PUSHER env updated for mode=${mode}"
docker compose -f /data/coolify/source/docker-compose.yml \
               -f /data/coolify/source/docker-compose.prod.yml \
               up -d --no-deps coolify >/dev/null
EOF
}
