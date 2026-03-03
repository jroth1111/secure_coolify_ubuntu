#!/usr/bin/env bash
# lib/coolify-common.sh — Shared utilities for deploy.sh and setup.sh.
# Source this file; do not execute it directly.
# Requires: set -Eeuo pipefail in the caller.

[[ "${BASH_SOURCE[0]}" != "${0}" ]] \
  || { printf 'Source this file, do not execute it.\n' >&2; exit 1; }
[[ -z "${_COOLIFY_COMMON_LOADED:-}" ]] || return 0
_COOLIFY_COMMON_LOADED=1

# ── Regex patterns ──────────────────────────────────────────────────────────

IPV4_RE='^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
LINUX_USER_RE='^[a-z_][a-z0-9_-]*$'
FQDN_RE='^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
SWAP_RE='^[0-9]+[GM]$'

# ── Helpers ─────────────────────────────────────────────────────────────────

log()  { printf '[%s] %s\n' "$(date -Iseconds)" "$*"; }
warn() { log "WARN: $*"; }
die()  { log "FATAL: $*" >&2; exit 1; }
step() { printf '\n\033[1;36m[%s] %s\033[0m\n' "$1" "$2"; }
pass() { printf '  \033[1;32mPASS\033[0m %s\n' "$*"; }
fail() { printf '  \033[1;31mFAIL\033[0m %s\n' "$*"; }

is_true() {
  case "${1,,}" in
    1|true|yes|y|on) return 0 ;;
    *) return 1 ;;
  esac
}

confirm() {
  if is_true "${AUTO_YES}"; then return 0; fi
  local msg="${1:-Continue?}"
  printf '\n%s [y/N] ' "${msg}"
  read -r ans
  case "${ans,,}" in
    y|yes) return 0 ;;
    *) die "Aborted by user." ;;
  esac
}

# ── Input helpers ───────────────────────────────────────────────────────────

prompt_value() {
  local var_name="$1" prompt="$2" default="${3:-}" regex="${4:-}"
  local val
  # When --yes is set and a default exists, accept it without prompting
  if is_true "${AUTO_YES}" && [[ -n "${default}" ]]; then
    # Use declare -g for safer variable assignment (bash 4.2+)
    declare -g "${var_name}=${default}"
    return 0
  fi
  printf '%s' "${prompt}"
  [[ -n "${default}" ]] && printf ' [%s]' "${default}"
  printf ': '
  read -r val
  val="${val:-$default}"
  if [[ -n "${regex}" ]] && ! [[ "${val}" =~ ${regex} ]]; then
    die "Invalid input for ${var_name}: '${val}' does not match ${regex}"
  fi
  declare -g "${var_name}=${val}"
}

prompt_secret() {
  local var_name="$1" prompt="$2"
  local val
  printf '%s: ' "${prompt}"
  read -rs val
  printf '\n'
  [[ -n "${val}" ]] || die "${var_name} cannot be empty."
  declare -g "${var_name}=${val}"
}

prompt_choice() {
  local var_name="$1" prompt="$2" default="$3"
  shift 3
  local options=("$@")
  # When --yes is set, accept the default without prompting
  if is_true "${AUTO_YES}"; then
    declare -g "${var_name}=${default}"
    return 0
  fi
  printf '%s [%s] (%s): ' "${prompt}" "${default}" "$(IFS=/; echo "${options[*]}")"
  read -r val
  val="${val:-$default}"
  local valid=false
  for opt in "${options[@]}"; do
    [[ "${val}" == "${opt}" ]] && valid=true
  done
  ${valid} || die "Invalid choice for ${var_name}: '${val}'. Options: ${options[*]}"
  declare -g "${var_name}=${val}"
}

# ── Cloudflare API ─────────────────────────────────────────────────────────

cf_api() {
  local method="$1" endpoint="$2" body="${3:-}"
  local url="https://api.cloudflare.com/client/v4${endpoint}"
  local args=(-s -X "${method}" -H "Content-Type: application/json")
  [[ -n "${body}" ]] && args+=(-d "${body}")
  printf -- '-H "Authorization: Bearer %s"\n' "${CF_API_TOKEN}" \
    | curl --config - "${args[@]}" "${url}"
}

cf_verify_token() {
  # Use zones endpoint rather than /user/tokens/verify — the latter requires
  # User:User Tokens:Read which is not part of our required token permissions.
  local resp
  resp="$(cf_api GET /zones?per_page=1)"
  local status
  status="$(printf '%s' "${resp}" | jq -r '.success // false')"
  [[ "${status}" == "true" ]] || die "Cloudflare API token verification failed: $(printf '%s' "${resp}" | jq -r '.errors[0].message // "unknown"')"
  log "Cloudflare API token verified."
}

cf_get_zone_id() {
  # If --cf-zone was specified, use it directly
  if [[ -n "${CF_ZONE}" ]]; then
    local resp
    resp="$(cf_api GET "/zones?name=${CF_ZONE}&status=active")"
    CF_ZONE_ID="$(printf '%s' "${resp}" | jq -r '.result[0].id // empty')"
    [[ -n "${CF_ZONE_ID}" ]] || die "Cloudflare zone not found for '${CF_ZONE}'. Check --cf-zone value."
    CF_ZONE_NAME="${CF_ZONE}"
    log "Cloudflare zone ID: ${CF_ZONE_ID} (${CF_ZONE_NAME})"
    return 0
  fi

  # Auto-detect zone by trying progressively shorter suffixes of DOMAIN.
  # This correctly handles multi-part TLDs (e.g. .com.au, .co.uk) where
  # stripping only the first label would give a non-existent zone.
  local candidate="${DOMAIN}"
  while [[ "${candidate}" == *.* ]]; do
    local resp
    resp="$(cf_api GET "/zones?name=${candidate}&status=active")"
    CF_ZONE_ID="$(printf '%s' "${resp}" | jq -r '.result[0].id // empty')"
    if [[ -n "${CF_ZONE_ID}" ]]; then
      CF_ZONE_NAME="${candidate}"
      log "Cloudflare zone ID: ${CF_ZONE_ID} (${CF_ZONE_NAME})"
      return 0
    fi
    candidate="${candidate#*.}"  # strip leftmost label and retry
  done
  die "Cloudflare zone not found for any suffix of '${DOMAIN}'. Check domain or use --cf-zone."
}

cf_get_account_id() {
  local resp
  resp="$(cf_api GET /accounts)"
  CF_ACCOUNT_ID="$(printf '%s' "${resp}" | jq -r '.result[0].id // empty')"
  [[ -n "${CF_ACCOUNT_ID}" ]] || die "No Cloudflare account found."
  log "Cloudflare account ID: ${CF_ACCOUNT_ID}"
}

cf_expect_success() {
  local action="$1" resp="$2"
  local success
  success="$(printf '%s' "${resp}" | jq -r '.success // false' 2>/dev/null || echo "false")"
  if [[ "${success}" != "true" ]]; then
    local err
    err="$(printf '%s' "${resp}" | jq -r '[.errors[]?.message] | join("; ")' 2>/dev/null || true)"
    [[ -n "${err}" && "${err}" != "null" ]] || err="unknown"
    die "${action} failed: ${err}"
  fi
}

cf_upsert_a_record() {
  local name="$1" ip="$2" proxied="${3:-true}"
  local existing
  existing="$(cf_api GET "/zones/${CF_ZONE_ID}/dns_records?type=A&name=${name}")"
  local record_id
  record_id="$(printf '%s' "${existing}" | jq -r '.result[0].id // empty')"
  local body
  body="$(jq -n --arg name "${name}" --arg ip "${ip}" --argjson proxied "${proxied}" \
    '{type:"A",name:$name,content:$ip,proxied:$proxied,ttl:1}')"
  local resp

  if [[ -n "${record_id}" ]]; then
    resp="$(cf_api PUT "/zones/${CF_ZONE_ID}/dns_records/${record_id}" "${body}")"
    cf_expect_success "Cloudflare A record update (${name})" "${resp}"
    log "Updated A record: ${name} → ${ip} (proxied=${proxied})"
  else
    resp="$(cf_api POST "/zones/${CF_ZONE_ID}/dns_records" "${body}")"
    cf_expect_success "Cloudflare A record create (${name})" "${resp}"
    log "Created A record: ${name} → ${ip} (proxied=${proxied})"
  fi
}

cf_create_tunnel() {
  local stop_fn="${1:-}"   # optional: name of function to call to stop cloudflared
  local tunnel_name="${DOMAIN%%.*}-coolify"

  # Delete any existing tunnel with the same name (idempotent re-run support).
  # Stop cloudflared first so it releases active connections — the CF API rejects DELETE for
  # tunnels with active connections, and the name stays reserved even after a failed delete.
  local existing_id
  existing_id="$(cf_api GET "/accounts/${CF_ACCOUNT_ID}/cfd_tunnel?name=${tunnel_name}&is_deleted=false" \
    | jq -r '.result[0].id // empty')"
  if [[ -n "${existing_id}" ]]; then
    log "Stopping cloudflared on server to release tunnel connections before delete..."
    [[ -n "${stop_fn}" ]] && "${stop_fn}"
    sleep 3  # Allow connections to close
    log "Deleting stale tunnel ${tunnel_name} (${existing_id}) before recreating..."
    local delete_resp delete_ok delete_err
    delete_resp="$(cf_api DELETE "/accounts/${CF_ACCOUNT_ID}/cfd_tunnel/${existing_id}" 2>/dev/null || true)"
    delete_ok="$(printf '%s' "${delete_resp}" | jq -r '.success // false' 2>/dev/null || echo "false")"
    if [[ "${delete_ok}" == "true" ]]; then
      log "Deleted stale tunnel ${existing_id}"
    else
      delete_err="$(printf '%s' "${delete_resp}" | jq -r '[.errors[]?.message] | join("; ")' 2>/dev/null || true)"
      [[ -n "${delete_err}" && "${delete_err}" != "null" ]] || delete_err="unknown"
      warn "Could not delete stale tunnel ${existing_id} (${delete_err}); proceeding anyway."
    fi
    sleep 2  # Allow CF to release the name
  fi

  TUNNEL_SECRET="$(openssl rand -base64 32)"
  local body
  body="$(jq -n --arg name "${tunnel_name}" --arg secret "${TUNNEL_SECRET}" \
    '{name:$name,tunnel_secret:$secret,config_src:"local"}')"
  local resp
  resp="$(cf_api POST "/accounts/${CF_ACCOUNT_ID}/cfd_tunnel" "${body}")"
  TUNNEL_ID="$(printf '%s' "${resp}" | jq -r '.result.id // empty')"
  [[ -n "${TUNNEL_ID}" ]] || die "Failed to create Cloudflare Tunnel: $(printf '%s' "${resp}" | jq -r '.errors[0].message // "unknown"')"
  log "Created tunnel: ${tunnel_name} (${TUNNEL_ID})"
}

cf_upsert_cname() {
  local name="$1" target="$2"
  local existing
  existing="$(cf_api GET "/zones/${CF_ZONE_ID}/dns_records?type=CNAME&name=${name}")"
  local record_id
  record_id="$(printf '%s' "${existing}" | jq -r '.result[0].id // empty')"
  local body
  body="$(jq -n --arg name "${name}" --arg target "${target}" \
    '{type:"CNAME",name:$name,content:$target,proxied:true,ttl:1}')"
  local resp

  if [[ -n "${record_id}" ]]; then
    resp="$(cf_api PUT "/zones/${CF_ZONE_ID}/dns_records/${record_id}" "${body}")"
    cf_expect_success "Cloudflare CNAME update (${name})" "${resp}"
    log "Updated CNAME: ${name} → ${target}"
  else
    resp="$(cf_api POST "/zones/${CF_ZONE_ID}/dns_records" "${body}")"
    cf_expect_success "Cloudflare CNAME create (${name})" "${resp}"
    log "Created CNAME: ${name} → ${target}"
  fi
}

# ── Shared deployment helpers ────────────────────────────────────────────────

# report_validation_result — Parse and report validate_hardening.sh JSON output.
# Caller captures JSON (via SSH or locally) and passes it in as the second argument.
# Usage: report_validation_result "Gate C" "${validate_json}" "Gate C failed. ..."
report_validation_result() {
  local label="$1" validate_json="$2" die_msg="$3"
  local fail_count
  fail_count="$(printf '%s' "${validate_json}" | jq -r '.fail // -1' 2>/dev/null || echo "-1")"
  if [[ "${fail_count}" == "0" ]]; then
    pass "${label}: validate_hardening.sh — 0 failures"
  else
    fail "${label}: validate_hardening.sh reported ${fail_count} failures"
    printf '%s\n' "${validate_json}" | jq '.checks[] | select(.status=="FAIL")' 2>/dev/null || true
    die "${die_msg}"
  fi
}

# coolify_install_docker_engine_script — Emit host-side script to install Docker
# via the official apt repository (no convenience curl|sh installer).
coolify_install_docker_engine_script() {
  cat <<'EOF'
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
source /etc/os-release
codename="${VERSION_CODENAME:-}"
[[ -n "${codename}" ]] || { echo "VERSION_CODENAME missing in /etc/os-release" >&2; exit 1; }

apt-get update -qq
apt-get install -y -qq ca-certificates curl gnupg
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
cat > /etc/apt/sources.list.d/docker.list <<REPO
deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${codename} stable
REPO
apt-get update -qq
apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
EOF
}

# coolify_install_coolify_script — Emit host-side script to install Coolify by
# downloading installer to a local temp file, validating basic format, then executing it.
coolify_install_coolify_script() {
  cat <<'EOF'
set -Eeuo pipefail
installer_url="https://cdn.coollabs.io/coolify/install.sh"
tmp="$(mktemp /tmp/coolify-install.XXXXXX.sh)"
cleanup() { rm -f "${tmp}"; }
trap cleanup EXIT

curl -fsSL "${installer_url}" -o "${tmp}"
[[ -s "${tmp}" ]] || { echo "Downloaded Coolify installer is empty" >&2; exit 1; }
head -1 "${tmp}" | grep -Eq '^#!.*/(ba)?sh$' || { echo "Unexpected Coolify installer header" >&2; exit 1; }
chmod 700 "${tmp}"
bash "${tmp}"
EOF
}

# coolify_reconcile_docker_daemon_script — Emit a host-side script that enforces
# daemon.json hardening keys while preserving unrelated settings.
# Caller is responsible for transport/execution (local bash -s vs remote sudo bash -s).
coolify_reconcile_docker_daemon_script() {
  cat <<'EOF'
set -Eeuo pipefail
daemon_json="/etc/docker/daemon.json"
state_file="/var/lib/bootstrap-hardening/state"
nproc_hard="8192"
nproc_soft="4096"
tmp="$(mktemp)"

if [[ -f "${state_file}" ]]; then
  nproc_hard="$(grep -m1 '^docker_nproc_hard=' "${state_file}" | cut -d= -f2- || echo "8192")"
  nproc_soft="$(grep -m1 '^docker_nproc_soft=' "${state_file}" | cut -d= -f2- || echo "4096")"
fi
[[ "${nproc_hard}" =~ ^[1-9][0-9]*$ ]] || nproc_hard="8192"
[[ "${nproc_soft}" =~ ^[1-9][0-9]*$ ]] || nproc_soft="4096"
if (( nproc_soft > nproc_hard )); then
  nproc_soft="${nproc_hard}"
fi

if [[ -f "${daemon_json}" ]]; then
  current_driver="$(jq -r '.["log-driver"] // ""' "${daemon_json}" 2>/dev/null || true)"
  if [[ "${current_driver}" != "" && "${current_driver}" != "json-file" ]]; then
    echo "WARNING: Docker log-driver drift detected (was '${current_driver}', expected 'json-file'). Reconciling..." >&2
  fi
  current_live_restore="$(jq -r '.["live-restore"] // ""' "${daemon_json}" 2>/dev/null || true)"
  if [[ "${current_live_restore}" != "" && "${current_live_restore}" != "true" ]]; then
    echo "WARNING: Docker live-restore drift detected (was '${current_live_restore}', expected 'true'). Reconciling..." >&2
  fi
  current_ipc_mode="$(jq -r '.["default-ipc-mode"] // ""' "${daemon_json}" 2>/dev/null || true)"
  if [[ "${current_ipc_mode}" != "" && "${current_ipc_mode}" != "private" ]]; then
    echo "WARNING: Docker default-ipc-mode drift detected (was '${current_ipc_mode}', expected 'private'). Reconciling..." >&2
  fi
  current_storage_driver="$(jq -r '.["storage-driver"] // ""' "${daemon_json}" 2>/dev/null || true)"
  if [[ "${current_storage_driver}" != "" && "${current_storage_driver}" != "overlay2" ]]; then
    echo "WARNING: Docker storage-driver drift detected (was '${current_storage_driver}', expected 'overlay2'). Reconciling..." >&2
  fi
fi

if [[ -f "${daemon_json}" ]]; then
  jq \
    --argjson nproc_hard "${nproc_hard}" \
    --argjson nproc_soft "${nproc_soft}" \
    '. + {
      "log-driver":"json-file",
      "log-opts":((.["log-opts"] // {}) + {"max-size":"10m","max-file":"3"}),
      "live-restore":true,
      "default-ipc-mode":"private",
      "storage-driver":"overlay2",
      "default-ulimits":((.["default-ulimits"] // {}) + {
        "nofile":{"Name":"nofile","Hard":65536,"Soft":65536},
        "nproc":{"Name":"nproc","Hard":$nproc_hard,"Soft":$nproc_soft}
      })
    }' "${daemon_json}" > "${tmp}"
else
  jq -n \
    --argjson nproc_hard "${nproc_hard}" \
    --argjson nproc_soft "${nproc_soft}" \
    '{
      "log-driver":"json-file",
      "log-opts":{"max-size":"10m","max-file":"3"},
      "live-restore":true,
      "default-ipc-mode":"private",
      "storage-driver":"overlay2",
      "default-ulimits":{
        "nofile":{"Name":"nofile","Hard":65536,"Soft":65536},
        "nproc":{"Name":"nproc","Hard":$nproc_hard,"Soft":$nproc_soft}
      }
    }' > "${tmp}"
fi

if [[ -f "${daemon_json}" ]] && cmp -s "${tmp}" "${daemon_json}"; then
  rm -f "${tmp}"
  exit 0
fi

if [[ -f "${daemon_json}" ]]; then
  cp -a "${daemon_json}" "${daemon_json}.bak.$(date +%s)"
fi

cat "${tmp}" > "${daemon_json}"
chmod 0644 "${daemon_json}"
rm -f "${tmp}"
systemctl restart docker
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
sql="UPDATE server_settings SET wildcard_domain = 'http://${APP_DOMAIN}' WHERE server_id = 0;"
docker exec -i coolify-db sh -ceu '
  IFS= read -r PGPASSWORD
  export PGPASSWORD
  psql -v ON_ERROR_STOP=1 -U "$1" -d "$2" -c "$3" >/dev/null
' _ "${db_user}" "${db_name}" "${sql}" <<< "${db_pass}"
EOF
}

# coolify_reconcile_pusher_env_script — Emit host-side script to reconcile
# PUSHER_* environment variables by deployment mode. Requires DEPLOY_MODE, DOMAIN.
coolify_reconcile_pusher_env_script() {
  cat <<'EOF'
set -Eeuo pipefail
: "${DEPLOY_MODE:?DEPLOY_MODE is required}"
: "${DOMAIN:?DOMAIN is required}"
coolify_env="/data/coolify/source/.env"
mode="${DEPLOY_MODE}"
tmp="$(mktemp)"
sed '/^PUSHER_HOST=/d; /^PUSHER_PORT=/d; /^PUSHER_SCHEME=/d' "${coolify_env}" > "${tmp}"

if [[ "${mode}" == "tunnel" ]]; then
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
               up -d --force-recreate coolify soketi 2>&1 | tail -5
EOF
}

# coolify_add_coolify_root_key_script — Emit host-side script that inserts Coolify's
# generated SSH public key into /root/.ssh/authorized_keys idempotently.
coolify_add_coolify_root_key_script() {
  cat <<'EOF'
set -Eeuo pipefail
keyfile="$(ls /data/coolify/ssh/keys/ssh_key@* 2>/dev/null | head -1 || true)"
[[ -n "${keyfile}" ]] || { echo "No Coolify SSH key found — skipping"; exit 0; }
pubkey="$(ssh-keygen -y -f "${keyfile}")"
auth="/root/.ssh/authorized_keys"
mkdir -p /root/.ssh && chmod 700 /root/.ssh
touch "${auth}" && chmod 600 "${auth}"
tmp="$(mktemp)"
awk '
  $1 ~ /^(ssh-(rsa|ed25519|dss)|ecdsa-[^[:space:]]+)$/ && NF >= 2 {
    if (!seen[$2]++) {
      print $1 " " $2
    }
  }
' "${auth}" > "${tmp}" 2>/dev/null || true
key_data="$(awk '{print $2}' <<< "${pubkey}")"
if awk '{print $2}' "${tmp}" 2>/dev/null | grep -qxF "${key_data}"; then
  echo "Coolify key already in root authorized_keys"
else
  printf '%s\n' "${pubkey}" >> "${tmp}"
  echo "Coolify key added to root authorized_keys"
fi
install -m 600 "${tmp}" "${auth}"
rm -f "${tmp}"
EOF
}

# coolify_fix_host_docker_internal_script — Emit host-side script that patches
# host.docker.internal in Coolify compose files to the current coolify bridge gateway.
coolify_fix_host_docker_internal_script() {
  cat <<'EOF'
set -Eeuo pipefail
compose_yml="/data/coolify/source/docker-compose.yml"
[[ -f "${compose_yml}" ]] || { echo "docker-compose.yml not found — skipping"; exit 0; }
gateway="$(docker network inspect coolify --format '{{range .IPAM.Config}}{{.Subnet}} {{.Gateway}} {{end}}' 2>/dev/null \
  | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | grep -v '/[0-9]' | head -1 || true)"
if [[ -z "${gateway}" ]]; then
  echo "Cannot determine coolify network gateway — skipping host.docker.internal fix"
  exit 0
fi
current="$(grep -m1 'host\.docker\.internal:' "${compose_yml}" | awk -F: '{print $NF}' | tr -d ' ' || true)"
if [[ "${current}" == "${gateway}" ]]; then
  echo "host.docker.internal already set to ${gateway}"
  exit 0
fi
sed -i "s|host\.docker\.internal:.*|host.docker.internal:${gateway}|g" "${compose_yml}"
echo "Patched host.docker.internal → ${gateway}"
docker compose -f /data/coolify/source/docker-compose.yml \
               -f /data/coolify/source/docker-compose.prod.yml \
               up -d --force-recreate coolify soketi 2>&1 | tail -5
EOF
}

# coolify_install_cloudflared_script — Emit host-side script to install cloudflared
# with apt first, then Cloudflare repo fallback.
coolify_install_cloudflared_script() {
  cat <<'EOF'
set -Eeuo pipefail
if bash -c "apt-get update -qq && apt-get install -y -qq cloudflared" 2>/dev/null; then
  exit 0
fi
echo "Trying Cloudflare repository..."
bash -o pipefail -c "curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null"
bash -c "echo \"deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared \$(lsb_release -cs) main\" | tee /etc/apt/sources.list.d/cloudflared.list >/dev/null"
bash -c "apt-get update -qq && apt-get install -y -qq cloudflared"
EOF
}

# coolify_configure_cloudflared_script — Emit host-side script to write tunnel creds/config
# and start cloudflared service. Requires TUNNEL_ID, TUNNEL_SECRET, CF_ACCOUNT_ID, DOMAIN,
# APP_DOMAIN, CF_ZONE_NAME in environment.
coolify_configure_cloudflared_script() {
  cat <<'EOF'
set -Eeuo pipefail
: "${TUNNEL_ID:?TUNNEL_ID is required}"
: "${TUNNEL_SECRET:?TUNNEL_SECRET is required}"
: "${CF_ACCOUNT_ID:?CF_ACCOUNT_ID is required}"
: "${DOMAIN:?DOMAIN is required}"
: "${APP_DOMAIN:?APP_DOMAIN is required}"
: "${CF_ZONE_NAME:?CF_ZONE_NAME is required}"

creds_json="$(jq -n --arg id "${TUNNEL_ID}" --arg secret "${TUNNEL_SECRET}" --arg account "${CF_ACCOUNT_ID}" \
  '{AccountTag:$account,TunnelID:$id,TunnelSecret:$secret}')"
mkdir -p /etc/cloudflared
printf '%s' "${creds_json}" > "/etc/cloudflared/${TUNNEL_ID}.json"
chmod 600 "/etc/cloudflared/${TUNNEL_ID}.json"

extra_apex_ingress=""
if [[ "${APP_DOMAIN}" != "${CF_ZONE_NAME}" ]]; then
  extra_apex_ingress="  - hostname: \"*.${CF_ZONE_NAME}\"
    service: http://localhost:80
"
fi
cat > /etc/cloudflared/config.yml <<CFG
tunnel: ${TUNNEL_ID}
credentials-file: /etc/cloudflared/${TUNNEL_ID}.json

ingress:
  - hostname: ${DOMAIN}
    path: /terminal/ws
    service: http://localhost:6002
  - hostname: ${DOMAIN}
    service: http://localhost:8000
  - hostname: ws.${DOMAIN}
    service: http://localhost:6001
  - hostname: "*.${APP_DOMAIN}"
    service: http://localhost:80
${extra_apex_ingress}  - service: http_status:404
CFG

cloudflared service install 2>/dev/null || true
systemctl enable --now cloudflared
EOF
}

# collect_common_inputs — Prompt for inputs shared by both deploy.sh and setup.sh.
# Each script calls this then adds its own script-specific prompts.
collect_common_inputs() {
  [[ -n "${SERVER_IP}" ]]   || prompt_value  SERVER_IP "Server public IP" "" "${IPV4_RE}"
  [[ -n "${ADMIN_USER}" ]]  || prompt_value  ADMIN_USER "Admin username" "coolifyadmin" "${LINUX_USER_RE}"
  [[ -n "${PUBKEY_FILE}" ]] || prompt_value  PUBKEY_FILE "SSH public key file" "${HOME}/.ssh/id_ed25519.pub"
  [[ -n "${TAILSCALE_AUTH_KEY}" ]] || prompt_value TAILSCALE_AUTH_KEY "Tailscale auth key (tskey-auth-...)" ""
  [[ -n "${DEPLOY_MODE}" ]] || prompt_choice DEPLOY_MODE "Deployment mode" "tunnel" "tunnel" "standard"
  [[ -n "${DOMAIN}" ]]      || prompt_value  DOMAIN "Domain name (FQDN)" "" "${FQDN_RE}"
  [[ -n "${CF_API_TOKEN}" ]] || prompt_secret CF_API_TOKEN "Cloudflare API token"
  # CF_ZONE intentionally left as-is (derived from domain when empty; --cf-zone overrides)
  [[ -n "${SWAP_SIZE}" ]]   || SWAP_SIZE="2G"
  # App subdomain scope: where Coolify auto-assigns app URLs.
  #   apex → appname.CF_ZONE     e.g. appname.example.com      (default — Free Universal SSL)
  #   vps  → appname.DOMAIN      e.g. appname.vps.example.com  (server-scoped; needs ACM/Enterprise for proxied SSL)
  if [[ -z "${APP_DOMAIN_MODE}" ]]; then
    printf '  App subdomain scope:\n'
    printf '    apex → appname.ZONE_APEX                (default — works with Cloudflare Free SSL)\n'
    printf '    vps  → appname.%s  (scoped to this server; requires paid ACM or Enterprise for proxied SSL)\n' "${DOMAIN:-DOMAIN}"
    prompt_choice APP_DOMAIN_MODE "App subdomain scope" "apex" "apex" "vps"
  fi
}

# resolve_app_domain — Set APP_DOMAIN from APP_DOMAIN_MODE after CF_ZONE_NAME is known.
# Call this after cf_get_zone_id.
resolve_app_domain() {
  if [[ "${APP_DOMAIN_MODE}" == "apex" ]]; then
    APP_DOMAIN="${CF_ZONE_NAME}"
  else
    APP_DOMAIN="${DOMAIN}"
    if [[ "${DOMAIN}" != "${CF_ZONE_NAME}" ]]; then
      warn "vps mode: DOMAIN (${DOMAIN}) is a subdomain of zone ${CF_ZONE_NAME}."
      warn "Apps at appname.${DOMAIN} are two levels deep and NOT covered by Cloudflare Free Universal SSL."
      warn "Use --app-domain-mode apex for free proxied SSL, or provision ACM / CF for SaaS manually."
    fi
  fi
  log "App subdomain scope: ${APP_DOMAIN_MODE} — new apps at appname.${APP_DOMAIN}"
}

# print_deployment_summary — Print completion banner and next-steps block.
# Uses globals: SERVER_IP, TS_IP, ADMIN_USER, DEPLOY_MODE, DOMAIN, CF_ZONE_NAME, APP_DOMAIN, TUNNEL_ID
print_deployment_summary() {
  printf '\n'
  printf '┌─────────────────────────────────────────────────────────────┐\n'
  printf '│                    DEPLOYMENT COMPLETE                      │\n'
  printf '├─────────────────────────────────────────────────────────────┤\n'
  printf '│  Server Public IP : %-40s│\n' "${SERVER_IP}"
  printf '│  Tailscale IP     : %-40s│\n' "${TS_IP}"
  printf '│  Admin User       : %-40s│\n' "${ADMIN_USER}"
  printf '│  Deploy Mode      : %-40s│\n' "${DEPLOY_MODE}"
  printf '│  Domain           : %-40s│\n' "${DOMAIN}"
  printf '│  Dashboard URL    : %-40s│\n' "http://${TS_IP}:8000"
  printf '│  SSH Access       : ssh %-36s│\n' "${ADMIN_USER}@${TS_IP}"
  printf '├─────────────────────────────────────────────────────────────┤\n'
  if [[ "${DEPLOY_MODE}" == "standard" ]]; then
    printf '│  DNS              : A %-38s│\n' "${DOMAIN} → ${SERVER_IP}"
    printf '│  Wildcard DNS     : A *.%-36s│\n' "${APP_DOMAIN}"
    [[ "${APP_DOMAIN}" != "${CF_ZONE_NAME}" ]] \
      && printf '│                   + A *.%-36s│\n' "${CF_ZONE_NAME}"
  else
    printf '│  DNS              : CNAME %-34s│\n' "${DOMAIN}"
    printf '│  Wildcard DNS     : CNAME *.%-32s│\n' "${APP_DOMAIN}"
    [[ "${APP_DOMAIN}" != "${CF_ZONE_NAME}" ]] \
      && printf '│                   + CNAME *.%-32s│\n' "${CF_ZONE_NAME}"
    printf '│  Tunnel ID        : %-40s│\n' "${TUNNEL_ID}"
    printf '│  WebSocket (Soketi): ws.%-36s│\n' "${DOMAIN} → tunnel"
    printf '│  Terminal         : %-40s│\n' "${DOMAIN}/terminal/ws → tunnel"
  fi
  printf '└─────────────────────────────────────────────────────────────┘\n'
  printf '\n'
  log "Next steps:"
  log "  1. Open http://${TS_IP}:8000 and create your Coolify admin account."
  log ""
  log "  2. Cloudflare SSL mode (one-time):"
  log "       Cloudflare dashboard > your zone > SSL/TLS > Overview > set to 'Full'"
  log "       (not Full Strict — Coolify uses self-signed certs internally)"
  log ""
  log "  3. Start the proxy: Coolify UI > Servers > localhost > Proxy > Start Proxy"
  log "       (required for app subdomains to route through Traefik)"
  log ""
  log "  4. Wildcard Domain is already set to http://${APP_DOMAIN} (done automatically)."
  log "       New apps will get  http://appname.${APP_DOMAIN}"
  log "       If an app already has a sslip.io URL: App > Settings > Domains > update it."
  log ""
  log "  5. For each app deployment in Coolify:"
  log "       Use http:// domain (not https://) — Cloudflare proxy adds TLS."
  log "       Example:  http://myapp.${APP_DOMAIN}"
  log ""
  log "  6. Deploy your first app — it gets a subdomain + Cloudflare SSL automatically."
}
