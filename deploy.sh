#!/usr/bin/env bash
set -Eeuo pipefail

# deploy.sh — Laptop-side orchestrator for secure Coolify deployment
# Runs on the operator's machine; SSHes into the remote server.
#
# Interactive mode:  ./deploy.sh
# Non-interactive:   ./deploy.sh --server-ip 1.2.3.4 --root-pass ... --yes
# Mixed:             ./deploy.sh --server-ip 1.2.3.4  (prompted for the rest)

SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── Inputs (populated by flags or prompts) ──────────────────────────────────

SERVER_IP="${SERVER_IP:-}"
ROOT_PASS="${ROOT_PASS:-}"
ADMIN_USER="${ADMIN_USER:-}"
PUBKEY_FILE="${PUBKEY_FILE:-}"
TAILSCALE_AUTH_KEY="${TAILSCALE_AUTH_KEY:-}"
DEPLOY_MODE="${DEPLOY_MODE:-}"
DOMAIN="${DOMAIN:-}"
CF_API_TOKEN="${CF_API_TOKEN:-}"
CF_ZONE="${CF_ZONE:-}"
SWAP_SIZE="${SWAP_SIZE:-}"
AUTO_YES="${AUTO_YES:-false}"
SKIP_HARDEN="${SKIP_HARDEN:-false}"  # set via --ts-ip to resume after partial harden

# ── Derived at runtime ──────────────────────────────────────────────────────

ADMIN_PUBKEY=""
PRIVATE_KEY=""
TS_IP=""
CF_ZONE_ID=""
CF_ZONE_NAME=""
CF_ACCOUNT_ID=""
TUNNEL_ID=""
TUNNEL_SECRET=""

# ── Regex patterns ──────────────────────────────────────────────────────────

IPV4_RE='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
LINUX_USER_RE='^[a-z_][a-z0-9_-]*$'
FQDN_RE='^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
SWAP_RE='^[0-9]+[GM]$'

# ── SSH options ─────────────────────────────────────────────────────────────

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR"

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
    eval "${var_name}=\${default}"
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
  eval "${var_name}=\${val}"
}

prompt_secret() {
  local var_name="$1" prompt="$2"
  printf '%s: ' "${prompt}"
  read -rs val
  printf '\n'
  [[ -n "${val}" ]] || die "${var_name} cannot be empty."
  eval "${var_name}=\${val}"
}

prompt_choice() {
  local var_name="$1" prompt="$2" default="$3"
  shift 3
  local options=("$@")
  # When --yes is set, accept the default without prompting
  if is_true "${AUTO_YES}"; then
    eval "${var_name}=\${default}"
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
  eval "${var_name}=\${val}"
}

# ── Usage ───────────────────────────────────────────────────────────────────

usage() {
  cat <<'EOF'
deploy.sh — Laptop-side orchestrator for secure Coolify deployment

Usage:
  deploy.sh [options]

If all required flags are provided, runs non-interactively.
If any are missing, prompts for them (mixed mode supported).

Required:
  --server-ip <ip>              Server public IPv4 address
  --root-pass <pass>            Root password for initial SSH
  --tailscale-auth-key <key>    Tailscale auth key (tskey-auth-...)
  --domain <fqdn>               Domain name for Coolify
  --cf-api-token <token>        Cloudflare API token

Optional:
  --admin-user <name>           Admin username (default: coolifyadmin)
  --pubkey-file <path>          SSH public key file (default: ~/.ssh/id_ed25519.pub)
  --mode <tunnel|standard>       Deployment mode (default: tunnel)
  --cf-zone <zone>              Cloudflare zone (default: derived from domain)
  --swap-size <size>            Swap size (default: 2G)
  --yes                         Skip confirmation prompts (for automation)
  --ts-ip <ip>                  Skip phase 1 (hardening already done); set Tailscale IP directly
  -h, --help                    Show this help
EOF
}

# ── Argument parsing ────────────────────────────────────────────────────────

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --server-ip)       SERVER_IP="${2:?--server-ip requires a value}"; shift 2 ;;
      --root-pass)       ROOT_PASS="${2:?--root-pass requires a value}"; shift 2 ;;
      --admin-user)      ADMIN_USER="${2:?--admin-user requires a value}"; shift 2 ;;
      --pubkey-file)     PUBKEY_FILE="${2:?--pubkey-file requires a value}"; shift 2 ;;
      --tailscale-auth-key) TAILSCALE_AUTH_KEY="${2:?--tailscale-auth-key requires a value}"; shift 2 ;;
      --mode)            DEPLOY_MODE="${2:?--mode requires a value}"; shift 2 ;;
      --domain)          DOMAIN="${2:?--domain requires a value}"; shift 2 ;;
      --cf-api-token)    CF_API_TOKEN="${2:?--cf-api-token requires a value}"; shift 2 ;;
      --cf-zone)         CF_ZONE="${2:?--cf-zone requires a value}"; shift 2 ;;
      --swap-size)       SWAP_SIZE="${2:?--swap-size requires a value}"; shift 2 ;;
      --yes)             AUTO_YES="true"; shift ;;
      --ts-ip)           TS_IP="${2:?--ts-ip requires a value}"; SKIP_HARDEN="true"; shift 2 ;;
      -h|--help)         usage; exit 0 ;;
      *)                 die "Unknown option: $1 (use --help)" ;;
    esac
  done
}

# ── Input collection (flag → prompt fallback) ──────────────────────────────

collect_inputs() {
  [[ -n "${SERVER_IP}" ]]   || prompt_value  SERVER_IP "Server public IP" "" "${IPV4_RE}"
  # ROOT_PASS not needed when --ts-ip is supplied (hardening already done)
  if ! is_true "${SKIP_HARDEN}"; then
    [[ -n "${ROOT_PASS}" ]] || prompt_secret ROOT_PASS "Root password"
  fi
  [[ -n "${ADMIN_USER}" ]]  || prompt_value  ADMIN_USER "Admin username" "coolifyadmin" "${LINUX_USER_RE}"
  [[ -n "${PUBKEY_FILE}" ]] || prompt_value  PUBKEY_FILE "SSH public key file" "${HOME}/.ssh/id_ed25519.pub"
  [[ -n "${TAILSCALE_AUTH_KEY}" ]] || prompt_value TAILSCALE_AUTH_KEY "Tailscale auth key (tskey-auth-...)" ""
  [[ -n "${DEPLOY_MODE}" ]] || prompt_choice DEPLOY_MODE "Deployment mode" "tunnel" "tunnel" "standard"
  [[ -n "${DOMAIN}" ]]      || prompt_value  DOMAIN "Domain name (FQDN)" "" "${FQDN_RE}"
  [[ -n "${CF_API_TOKEN}" ]] || prompt_secret CF_API_TOKEN "Cloudflare API token"
  [[ -n "${CF_ZONE}" ]]     || CF_ZONE=""  # will be derived from domain
  [[ -n "${SWAP_SIZE}" ]]   || SWAP_SIZE="2G"
}

# ── Input validation ───────────────────────────────────────────────────────

validate_inputs() {
  [[ "${SERVER_IP}" =~ ${IPV4_RE} ]]      || die "Invalid server IP: ${SERVER_IP}"
  # ROOT_PASS not required when --ts-ip is supplied (hardening already done)
  if ! is_true "${SKIP_HARDEN}"; then
    [[ -n "${ROOT_PASS}" ]]               || die "Root password is required."
  fi
  [[ "${ADMIN_USER}" =~ ${LINUX_USER_RE} ]] || die "Invalid admin username: ${ADMIN_USER}"
  [[ "${ADMIN_USER}" != "root" ]]          || die "Admin user must not be root."

  [[ -f "${PUBKEY_FILE}" ]]                || die "Public key file not found: ${PUBKEY_FILE}"
  ssh-keygen -l -f "${PUBKEY_FILE}" >/dev/null 2>&1 \
    || die "Invalid SSH public key: ${PUBKEY_FILE}"
  ADMIN_PUBKEY="$(cat "${PUBKEY_FILE}")"
  PRIVATE_KEY="${PUBKEY_FILE%.pub}"
  [[ -f "${PRIVATE_KEY}" ]] || die "Private key not found: ${PRIVATE_KEY} (expected alongside ${PUBKEY_FILE})"

  # Auth key only required when hardening will run; --ts-ip skips hardening.
  if ! is_true "${SKIP_HARDEN}"; then
    [[ "${TAILSCALE_AUTH_KEY}" == tskey-auth-* ]] \
      || die "Tailscale auth key must start with 'tskey-auth-' (got: ${TAILSCALE_AUTH_KEY:0:12}...)"
  fi

  # When resuming via --ts-ip, validate the supplied IP is a valid IPv4 address.
  if is_true "${SKIP_HARDEN}"; then
    [[ "${TS_IP}" =~ ${IPV4_RE} ]] \
      || die "Invalid Tailscale IP supplied via --ts-ip: '${TS_IP}'"
  fi

  [[ "${DEPLOY_MODE}" == "standard" || "${DEPLOY_MODE}" == "tunnel" ]] \
    || die "Mode must be 'standard' or 'tunnel' (got: ${DEPLOY_MODE})"

  [[ "${DOMAIN}" =~ ${FQDN_RE} ]]         || die "Invalid domain: ${DOMAIN}"
  [[ -n "${CF_API_TOKEN}" ]]               || die "Cloudflare API token is required."
  [[ "${SWAP_SIZE}" =~ ${SWAP_RE} ]]       || die "Invalid swap size: ${SWAP_SIZE} (expected e.g. 2G, 512M)"
}

# ── Cloudflare API ─────────────────────────────────────────────────────────

cf_api() {
  local method="$1" endpoint="$2" body="${3:-}"
  local url="https://api.cloudflare.com/client/v4${endpoint}"
  local args=(-s -X "${method}" -H "Authorization: Bearer ${CF_API_TOKEN}" -H "Content-Type: application/json")
  [[ -n "${body}" ]] && args+=(-d "${body}")
  curl "${args[@]}" "${url}"
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

cf_upsert_a_record() {
  local name="$1" ip="$2" proxied="${3:-true}"
  local existing
  existing="$(cf_api GET "/zones/${CF_ZONE_ID}/dns_records?type=A&name=${name}")"
  local record_id
  record_id="$(printf '%s' "${existing}" | jq -r '.result[0].id // empty')"
  local body
  body="$(jq -n --arg name "${name}" --arg ip "${ip}" --argjson proxied "${proxied}" \
    '{type:"A",name:$name,content:$ip,proxied:$proxied,ttl:1}')"

  if [[ -n "${record_id}" ]]; then
    cf_api PUT "/zones/${CF_ZONE_ID}/dns_records/${record_id}" "${body}" >/dev/null
    log "Updated A record: ${name} → ${ip} (proxied=${proxied})"
  else
    cf_api POST "/zones/${CF_ZONE_ID}/dns_records" "${body}" >/dev/null
    log "Created A record: ${name} → ${ip} (proxied=${proxied})"
  fi
}

cf_create_tunnel() {
  local tunnel_name="${DOMAIN%%.*}-coolify"

  # Delete any existing tunnel with the same name (idempotent re-run support).
  # Stop cloudflared first so it releases active connections — the CF API rejects DELETE for
  # tunnels with active connections, and the name stays reserved even after a failed delete.
  local existing_id
  existing_id="$(cf_api GET "/accounts/${CF_ACCOUNT_ID}/cfd_tunnel?name=${tunnel_name}&is_deleted=false" \
    | jq -r '.result[0].id // empty')"
  if [[ -n "${existing_id}" ]]; then
    log "Stopping cloudflared on server to release tunnel connections before delete..."
    ssh_admin_sudo 'systemctl stop cloudflared 2>/dev/null || true'
    sleep 3  # Allow connections to close
    log "Deleting stale tunnel ${tunnel_name} (${existing_id}) before recreating..."
    cf_api DELETE "/accounts/${CF_ACCOUNT_ID}/cfd_tunnel/${existing_id}" >/dev/null \
      || warn "Could not delete stale tunnel ${existing_id}; proceeding anyway."
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

  if [[ -n "${record_id}" ]]; then
    cf_api PUT "/zones/${CF_ZONE_ID}/dns_records/${record_id}" "${body}" >/dev/null
    log "Updated CNAME: ${name} → ${target}"
  else
    cf_api POST "/zones/${CF_ZONE_ID}/dns_records" "${body}" >/dev/null
    log "Created CNAME: ${name} → ${target}"
  fi
}

# ── SSH wrappers ────────────────────────────────────────────────────────────

ssh_root() {
  SSHPASS="${ROOT_PASS}" sshpass -e ssh ${SSH_OPTS} "root@${SERVER_IP}" "$@"
}

scp_root() {
  SSHPASS="${ROOT_PASS}" sshpass -e scp ${SSH_OPTS} "$@"
}

scp_admin() {
  scp ${SSH_OPTS} -i "${PRIVATE_KEY}" "$@"
}

ssh_admin() {
  ssh ${SSH_OPTS} -i "${PRIVATE_KEY}" "${ADMIN_USER}@${TS_IP}" "$@"
}

ssh_admin_sudo() {
  ssh ${SSH_OPTS} -i "${PRIVATE_KEY}" "${ADMIN_USER}@${TS_IP}" "sudo $*"
}

# Upload companion scripts to /root/ on the server using admin key + sudo.
# Called at start of phase 2 so all phases always use the latest local scripts,
# even when phase 1 (root SCP upload) was skipped via --ts-ip.
sync_companion_scripts() {
  local scripts=(bootstrap_hardening.sh validate_hardening.sh configure_coolify_binding.sh)
  log "Syncing companion scripts to server /root/..."
  for script in "${scripts[@]}"; do
    local path="${SCRIPT_DIR}/${script}"
    [[ -f "${path}" ]] || die "Script not found: ${path}"
    scp_admin "${path}" "${ADMIN_USER}@${TS_IP}:/tmp/${script}" \
      || die "Failed to upload ${script}"
    # Use bash -c so both mv and chmod run under sudo (&&-chain only elevates the first command)
    ssh_admin_sudo "bash -c 'mv /tmp/${script} /root/${script} && chmod 755 /root/${script}'" \
      || die "Failed to install ${script} to /root/"
  done
  pass "Companion scripts synced to server"
}

verify_docker_user_gate_remote() {
  local gate_label="$1"
  local gate_d_inactive_msg="Gate D failed: docker-user-hardening.service is not active."

  if ssh_admin_sudo 'systemctl is-active --quiet docker-user-hardening.service'; then
    pass "${gate_label}: docker-user-hardening.service is active"
  else
    fail "${gate_label}: docker-user-hardening.service is not active"
    die "${gate_d_inactive_msg}"
  fi

  local iptables_out
  iptables_out="$(ssh_admin_sudo 'iptables -S DOCKER-USER' 2>/dev/null)" || true
  if printf '%s' "${iptables_out}" | grep -q "coolify-hardening"; then
    pass "${gate_label}: DOCKER-USER hardening rules active"
  else
    fail "${gate_label}: DOCKER-USER hardening rules not found"
    die "${gate_label} failed. Check: sudo systemctl status docker-user-hardening.service"
  fi
}

reconcile_docker_daemon_remote() {
  log "Reconciling Docker daemon settings after Coolify install..."
  # Hardening owns: log-driver, log-opts, live-restore. Coolify may add: default-address-pools.
  # Using json-file driver to match Coolify's expectation for compatibility.
  ssh_admin 'sudo bash -s' <<'EOF'
set -Eeuo pipefail
daemon_json="/etc/docker/daemon.json"
tmp="$(mktemp)"

# Drift detection: warn if hardening keys were changed (e.g., by Coolify update)
if [[ -f "${daemon_json}" ]]; then
  current_driver="$(jq -r '.["log-driver"] // ""' "${daemon_json}" 2>/dev/null || true)"
  if [[ "${current_driver}" != "" && "${current_driver}" != "json-file" ]]; then
    echo "WARNING: Docker log-driver drift detected (was '${current_driver}', expected 'json-file'). Reconciling..." >&2
  fi
  current_live_restore="$(jq -r '.["live-restore"] // ""' "${daemon_json}" 2>/dev/null || true)"
  if [[ "${current_live_restore}" != "" && "${current_live_restore}" != "true" ]]; then
    echo "WARNING: Docker live-restore drift detected (was '${current_live_restore}', expected 'true'). Reconciling..." >&2
  fi
fi

if [[ -f "${daemon_json}" ]]; then
  jq '. + {"log-driver":"json-file","log-opts":((.["log-opts"] // {}) + {"max-size":"10m","max-file":"3"}),"live-restore":true}' "${daemon_json}" > "${tmp}"
else
  jq -n '{"log-driver":"json-file","log-opts":{"max-size":"10m","max-file":"3"},"live-restore":true}' > "${tmp}"
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
  pass "Docker daemon hardening reconciled (json-file log rotation + live-restore)"
}

run_final_validation_gate_remote() {
  log "Running final validate_hardening.sh..."
  local validate_json
  validate_json="$(ssh_admin_sudo '/root/validate_hardening.sh --json' 2>/dev/null)" || true
  local fail_count
  fail_count="$(printf '%s' "${validate_json}" | jq -r '.fail // -1' 2>/dev/null || echo "-1")"
  if [[ "${fail_count}" == "0" ]]; then
    pass "Final validation: validate_hardening.sh — 0 failures"
  else
    fail "Final validation: validate_hardening.sh reported ${fail_count} failures"
    printf '%s\n' "${validate_json}" | jq '.checks[] | select(.status=="FAIL")' 2>/dev/null || true
    die "Final validation failed. Resolve validation failures before considering deployment complete."
  fi
}

# ── Pre-flight ──────────────────────────────────────────────────────────────

preflight() {
  step "0/5" "Pre-flight checks"

  # Check local tools
  local required_cmds=(ssh scp curl jq sshpass ssh-keygen openssl)
  for cmd in "${required_cmds[@]}"; do
    command -v "${cmd}" >/dev/null 2>&1 || die "Required command not found: ${cmd}. Install it first."
  done
  pass "Local tools present: ${required_cmds[*]}"

  # Validate pubkey
  ssh-keygen -l -f "${PUBKEY_FILE}" >/dev/null 2>&1 || die "Invalid SSH public key file: ${PUBKEY_FILE}"
  pass "SSH public key valid: ${PUBKEY_FILE}"

  # Verify Cloudflare token
  cf_verify_token
  cf_get_zone_id
  cf_get_account_id  # always fetch — needed for tunnel (default mode)
  pass "Cloudflare API verified (zone: ${CF_ZONE_ID})"

  # Test SSH connectivity (skipped when --ts-ip is used; root SSH is disabled post-harden)
  if is_true "${SKIP_HARDEN}"; then
    log "Skipping root SSH check (--ts-ip mode; hardening already applied)."
  else
    log "Testing SSH to root@${SERVER_IP}..."
    if ssh_root 'echo ok' >/dev/null 2>&1; then
      pass "SSH root@${SERVER_IP} reachable"
    else
      die "Cannot SSH to root@${SERVER_IP}. Check IP and root password."
    fi
  fi
}

# ── Phase 1: Upload + Harden ───────────────────────────────────────────────

phase1_upload_harden() {
  step "1/5" "Upload scripts & harden server"

  # Upload scripts
  local scripts=(bootstrap_hardening.sh validate_hardening.sh configure_coolify_binding.sh)
  for script in "${scripts[@]}"; do
    local path="${SCRIPT_DIR}/${script}"
    [[ -f "${path}" ]] || die "Script not found: ${path}"
    scp_root "${path}" "root@${SERVER_IP}:/root/${script}"
    ssh_root "chmod +x /root/${script}"
  done
  pass "Scripts uploaded"

  # Write env file on server (avoids quoting issues with SSH pubkey)
  local tunnel_flag="false"
  [[ "${DEPLOY_MODE}" == "tunnel" ]] && tunnel_flag="true"

  ssh_root "cat > /root/deploy.env" <<EOF
ADMIN_USER=${ADMIN_USER}
ADMIN_PUBKEY="${ADMIN_PUBKEY}"
TAILSCALE_CIDR=100.64.0.0/10
SSH_PORT=22
TUNNEL_MODE=${tunnel_flag}
SWAP_SIZE=${SWAP_SIZE}
INSTALL_TAILSCALE=true
TAILSCALE_AUTH_KEY=${TAILSCALE_AUTH_KEY}
BIND_DASHBOARD_TO_TAILSCALE=false
EOF
  ssh_root "chmod 600 /root/deploy.env"
  pass "Environment file written"

  # Run hardening, streaming output to terminal while capturing it for TS_IP extraction.
  # After hardening, UFW blocks all SSH on the public IP (only tailscale0 allowed), so
  # we cannot open a new root SSH session to run 'tailscale ip -4'. Instead, bootstrap
  # prints 'HARDEN_RESULT_TAILSCALE_IP=<ip>' as the last stdout line; we parse that.
  log "Running bootstrap_hardening.sh (this may take a few minutes)..."
  local harden_tmp
  harden_tmp="$(mktemp)"
  # Use || { } to handle pipeline failure explicitly — PIPESTATUS after a pipeline is unreliable
  # when set -Eeuo pipefail is active because set -e exits the script before PIPESTATUS is read.
  ssh_root "/root/bootstrap_hardening.sh --env-file /root/deploy.env --install-tailscale --force" \
    2>&1 | tee "${harden_tmp}" \
    || { rm -f "${harden_tmp}"; die "bootstrap_hardening.sh failed. Check server logs: /var/log/bootstrap-hardening.log"; }
  pass "Hardening completed"

  # Extract Tailscale IP from captured bootstrap output (sentinel line)
  TS_IP="$(grep '^HARDEN_RESULT_TAILSCALE_IP=' "${harden_tmp}" | cut -d= -f2 | tr -d '[:space:]')"
  rm -f "${harden_tmp}"
  [[ -n "${TS_IP}" ]] || die "Failed to get Tailscale IP from bootstrap output."
  pass "Server Tailscale IP: ${TS_IP}"

  # Note: deploy.env cleanup is deferred to phase2_gates (ssh_admin_sudo after Gate B),
  # because root SSH via public IP is now blocked by UFW.
}

# ── Phase 2: Gate checks ───────────────────────────────────────────────────

phase2_gates() {
  step "2/5" "Gate checks (SSH transition to admin@tailscale)"

  # Gate A: SSH as admin via Tailscale IP using key auth
  log "Gate A: Testing SSH admin@${TS_IP} via key auth..."
  # (Gate A runs first so we know SSH works before syncing scripts)
  local attempt max_attempts=6 delay=10
  for (( attempt=1; attempt<=max_attempts; attempt++ )); do
    if ssh_admin 'echo ok' >/dev/null 2>&1; then
      pass "Gate A: SSH ${ADMIN_USER}@${TS_IP} works"
      break
    fi
    if (( attempt == max_attempts )); then
      fail "Gate A: Cannot SSH to ${ADMIN_USER}@${TS_IP} after ${max_attempts} attempts"
      die "Gate A failed. Tailscale peering may not be established. Check 'tailscale status' on both machines."
    fi
    log "  Attempt ${attempt}/${max_attempts} failed, retrying in ${delay}s (Tailscale peering may need time)..."
    sleep "${delay}"
  done

  # Gate B: Verify admin identity
  local whoami_result
  whoami_result="$(ssh_admin 'whoami' 2>/dev/null | tr -d '[:space:]')"
  if [[ "${whoami_result}" == "${ADMIN_USER}" ]]; then
    pass "Gate B: whoami=${ADMIN_USER}"
  else
    fail "Gate B: Expected ${ADMIN_USER}, got '${whoami_result}'"
    die "Gate B failed."
  fi

  # Clean up sensitive deploy.env left on server by phase 1.
  # Done here (not in phase 1) because post-hardening UFW blocks root SSH on the public IP.
  ssh_admin_sudo "rm -f /root/deploy.env" 2>/dev/null || true

  # Always re-sync companion scripts via admin SCP after Gate A/B confirm SSH works.
  # This ensures the latest versions are used even when phase 1 (root upload) was skipped.
  sync_companion_scripts

  # Gate C: Validation passes
  log "Gate C: Running validate_hardening.sh..."
  local validate_json
  validate_json="$(ssh_admin_sudo '/root/validate_hardening.sh --json' 2>/dev/null)" || true
  local fail_count
  fail_count="$(printf '%s' "${validate_json}" | jq -r '.fail // -1' 2>/dev/null || echo "-1")"
  if [[ "${fail_count}" == "0" ]]; then
    pass "Gate C: validate_hardening.sh — 0 failures"
  else
    fail "Gate C: validate_hardening.sh reported ${fail_count} failures"
    printf '%s\n' "${validate_json}" | jq '.checks[] | select(.status=="FAIL")' 2>/dev/null || true
    die "Gate C failed. Fix validation failures before continuing."
  fi
}

# ── Phase 3: Docker + Coolify ──────────────────────────────────────────────

phase3_docker_coolify() {
  step "3/5" "Install Docker & Coolify"

  # Install Docker (skip if already present — the install script is not idempotent on network errors)
  if ssh_admin_sudo 'docker version >/dev/null 2>&1'; then
    log "Docker already installed — skipping install."
  else
    log "Installing Docker..."
    # Use bash -c under sudo so the entire pipeline runs as root
    ssh_admin_sudo 'bash -c "curl -fsSL https://get.docker.com | sh"' \
      || die "Docker installation failed."
    pass "Docker installed"
  fi
  pass "Docker present"

  # Start DOCKER-USER hardening service
  ssh_admin_sudo 'systemctl start docker-user-hardening.service' \
    || die "Failed to start docker-user-hardening.service"

  # Gate D: Verify DOCKER-USER rules
  verify_docker_user_gate_remote "Gate D"

  # Install Coolify (skip if already running)
  if ssh_admin_sudo 'test -f /data/coolify/source/.env' >/dev/null 2>&1; then
    log "Coolify .env found — skipping install (already installed)."
    pass "Coolify already installed"
  else
    log "Installing Coolify (this may take a few minutes)..."
    # Use bash -c under sudo so the entire pipeline runs as root
    ssh_admin_sudo 'bash -c "curl -fsSL https://cdn.coollabs.io/coolify/install.sh | bash"' \
      || die "Coolify installation failed."
    pass "Coolify installed"
  fi

  # Coolify installer manages daemon.json; re-apply hardening settings while preserving its keys.
  reconcile_docker_daemon_remote

  # Docker restart can flush DOCKER-USER runtime rules; re-apply and verify.
  ssh_admin_sudo 'systemctl restart docker-user-hardening.service' \
    || die "Failed to restart docker-user-hardening.service after Docker daemon reconciliation."
  verify_docker_user_gate_remote "Gate D (post-Coolify)"
}

# ── Phase 4: Binding + DNS ─────────────────────────────────────────────────

phase4_binding_dns() {
  step "4/5" "Configure dashboard binding & DNS"

  # Wait for Coolify to write its .env file before binding (installer is async)
  log "Waiting for Coolify to initialize /data/coolify/source/.env..."
  local coolify_wait=0 coolify_max=120
  until ssh_admin_sudo 'test -f /data/coolify/source/.env' >/dev/null 2>&1; do
    (( coolify_wait += 5 ))
    if (( coolify_wait >= coolify_max )); then
      warn "Coolify .env not found after ${coolify_max}s — binding may fail; continuing."
      break
    fi
    sleep 5
  done

  # Run configure_coolify_binding.sh on server
  log "Binding Coolify dashboard to Tailscale IP..."
  ssh_admin_sudo "/root/configure_coolify_binding.sh --tailscale-ip ${TS_IP}" \
    || warn "configure_coolify_binding.sh returned non-zero (may be ok if Coolify is still starting)"
  pass "Dashboard binding configured"

  if [[ "${DEPLOY_MODE}" == "standard" ]]; then
    # Standard mode: A records pointing to server public IP (proxied)
    log "Configuring DNS: A record ${DOMAIN} → ${SERVER_IP} (proxied)..."
    cf_upsert_a_record "${DOMAIN}" "${SERVER_IP}" "true"
    pass "DNS A record configured: ${DOMAIN} → ${SERVER_IP}"

    # Wildcard A record for subdomains (*.example.com → server IP)
    local wildcard_name="*.${CF_ZONE_NAME}"
    log "Configuring DNS: wildcard A record ${wildcard_name} → ${SERVER_IP} (proxied)..."
    cf_upsert_a_record "${wildcard_name}" "${SERVER_IP}" "true"
    pass "DNS wildcard A record configured: ${wildcard_name} → ${SERVER_IP}"

  elif [[ "${DEPLOY_MODE}" == "tunnel" ]]; then
    # Tunnel mode: create tunnel, install cloudflared, CNAME
    log "Creating Cloudflare Tunnel..."
    cf_create_tunnel
    pass "Tunnel created: ${TUNNEL_ID}"

    # Install cloudflared on server
    log "Installing cloudflared on server..."
    # Use bash -c under sudo so the entire && chain runs as root (sudo only elevates the first
    # command when chaining with &&; bash -c ensures all commands inherit root privileges)
    ssh_admin_sudo 'bash -c "apt-get update -qq && apt-get install -y -qq cloudflared"' 2>/dev/null \
      || {
        # Fallback: add Cloudflare repo and install
        log "Trying Cloudflare repository..."
        ssh_admin_sudo 'bash -c "curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null"' \
          || die "Failed to add Cloudflare GPG key"
        ssh_admin_sudo 'bash -c "echo \"deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared \$(lsb_release -cs) main\" | tee /etc/apt/sources.list.d/cloudflared.list"' \
          || die "Failed to add Cloudflare repository"
        ssh_admin_sudo 'bash -c "apt-get update -qq && apt-get install -y -qq cloudflared"' \
          || die "Failed to install cloudflared"
      }
    pass "cloudflared installed"

    # Write tunnel credentials
    local creds_json
    creds_json="$(jq -n --arg id "${TUNNEL_ID}" --arg secret "${TUNNEL_SECRET}" --arg account "${CF_ACCOUNT_ID}" \
      '{AccountTag:$account,TunnelID:$id,TunnelSecret:$secret}')"
    ssh_admin_sudo "mkdir -p /etc/cloudflared"
    printf '%s' "${creds_json}" | ssh_admin_sudo "tee /etc/cloudflared/${TUNNEL_ID}.json >/dev/null"
    ssh_admin_sudo "chmod 600 /etc/cloudflared/${TUNNEL_ID}.json"

    # Write tunnel config with wildcard ingress for multi-app support
    local wildcard_hostname="*.${CF_ZONE_NAME}"
    ssh_admin_sudo "tee /etc/cloudflared/config.yml >/dev/null" <<EOF
tunnel: ${TUNNEL_ID}
credentials-file: /etc/cloudflared/${TUNNEL_ID}.json

ingress:
  - hostname: ${DOMAIN}
    service: http://localhost:80
  - hostname: "${wildcard_hostname}"
    service: http://localhost:80
  - service: http_status:404
EOF
    pass "Tunnel credentials and config written (with wildcard ${wildcard_hostname})"

    # Start cloudflared service
    ssh_admin_sudo 'cloudflared service install 2>/dev/null || true'
    ssh_admin_sudo 'systemctl enable --now cloudflared' \
      || die "Failed to start cloudflared service"
    pass "cloudflared service running"

    # Create CNAME records: exact domain + wildcard for subdomains
    local tunnel_target="${TUNNEL_ID}.cfargotunnel.com"
    cf_upsert_cname "${DOMAIN}" "${tunnel_target}"
    pass "DNS CNAME configured: ${DOMAIN} → ${tunnel_target}"

    local wildcard_name="*.${CF_ZONE_NAME}"
    cf_upsert_cname "${wildcard_name}" "${tunnel_target}"
    pass "DNS wildcard CNAME configured: ${wildcard_name} → ${tunnel_target}"
  fi
}

# ── Phase 5: Verification ─────────────────────────────────────────────────

phase5_verify() {
  step "5/5" "Final verification"

  # Gate E: Dashboard reachable on Tailscale, not on public IP
  log "Gate E: Checking dashboard accessibility..."
  sleep 5  # Give Coolify a moment

  local ts_code
  local pub_code
  local attempts=12
  local attempt
  local delay=10
  local gate_e_passed=false
  for (( attempt=1; attempt<=attempts; attempt++ )); do
    # curl -w '%{http_code}' writes "000" to stdout on connection errors and exits non-zero.
    # Using "|| echo '000'" would append a second "000" giving "000000". Use "|| true" and
    # slice to 3 chars to always get a 3-digit code regardless of curl exit status.
    ts_code="$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 10 "http://${TS_IP}:8000" 2>/dev/null)" || true
    pub_code="$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 "http://${SERVER_IP}:8000" 2>/dev/null)" || true
    ts_code="${ts_code:0:3}"
    pub_code="${pub_code:0:3}"
    if [[ "${ts_code}" != "000" && "${pub_code}" == "000" ]]; then
      gate_e_passed=true
      break
    fi
    if (( attempt < attempts )); then
      log "  Gate E not ready (tailscale=${ts_code}, public=${pub_code}); retrying in ${delay}s (${attempt}/${attempts})..."
      sleep "${delay}"
    fi
  done

  if [[ "${gate_e_passed}" != "true" ]]; then
    if [[ "${ts_code}" == "000" ]]; then
      fail "Gate E: dashboard not reachable on ${TS_IP}:8000"
      die "Gate E failed: dashboard not reachable via Tailscale."
    fi
    fail "Gate E: dashboard reachable on public IP ${SERVER_IP}:8000 (HTTP ${pub_code})"
    die "Gate E failed: dashboard reachable on public IP."
  fi

  pass "Gate E: Dashboard reachable on Tailscale IP (HTTP ${ts_code})"
  pass "Gate E: Dashboard NOT reachable on public IP (good)"

  # Final validation run
  run_final_validation_gate_remote

  # Print summary
  printf '\n'
  printf '┌─────────────────────────────────────────────────────────────┐\n'
  printf '│                    DEPLOYMENT COMPLETE                      │\n'
  printf '├─────────────────────────────────────────────────────────────┤\n'
  printf '│  Server Public IP : %-39s│\n' "${SERVER_IP}"
  printf '│  Tailscale IP     : %-39s│\n' "${TS_IP}"
  printf '│  Admin User       : %-39s│\n' "${ADMIN_USER}"
  printf '│  Deploy Mode      : %-39s│\n' "${DEPLOY_MODE}"
  printf '│  Domain           : %-39s│\n' "${DOMAIN}"
  printf '│  Dashboard URL    : %-39s│\n' "http://${TS_IP}:8000"
  printf '│  SSH Access       : ssh %s@%-28s│\n' "${ADMIN_USER}" "${TS_IP}"
  printf '├─────────────────────────────────────────────────────────────┤\n'
  if [[ "${DEPLOY_MODE}" == "standard" ]]; then
    printf '│  DNS              : A %s → %s│\n' "${DOMAIN}" "${SERVER_IP}"
    printf '│  Wildcard DNS     : A *.%-36s│\n' "${CF_ZONE_NAME}"
  else
    printf '│  DNS              : CNAME %s│\n' "${DOMAIN}"
    printf '│  Wildcard DNS     : CNAME *.%-33s│\n' "${CF_ZONE_NAME}"
    printf '│  Tunnel ID        : %-39s│\n' "${TUNNEL_ID}"
  fi
  printf '└─────────────────────────────────────────────────────────────┘\n'
  printf '\n'
  log "Next steps:"
  log "  1. Open http://${TS_IP}:8000 to create your Coolify admin account"
  log "  2. In Cloudflare dashboard: SSL/TLS > Overview > set mode to Full"
  log "  3. In Coolify: Servers > your server > Wildcard Domain > set to ${CF_ZONE_NAME}"
  log "  4. In Coolify: use http:// (not https://) for resource domains"
  log "  5. Deploy your first app — it gets a subdomain + SSL automatically!"
}

# ── Main ────────────────────────────────────────────────────────────────────

main() {
  parse_args "$@"
  collect_inputs
  validate_inputs

  # Show summary before proceeding
  printf '\n'
  log "Deployment configuration:"
  log "  Server:    ${SERVER_IP}"
  log "  Admin:     ${ADMIN_USER}"
  log "  Pubkey:    ${PUBKEY_FILE}"
  log "  Mode:      ${DEPLOY_MODE}"
  log "  Domain:    ${DOMAIN}"
  log "  Swap:      ${SWAP_SIZE}"
  confirm "Proceed with deployment?"

  preflight
  if is_true "${SKIP_HARDEN}"; then
    log "Skipping phase 1 (--ts-ip supplied; hardening already complete on ${TS_IP})"
  else
    phase1_upload_harden
  fi
  phase2_gates
  phase3_docker_coolify
  phase4_binding_dns
  phase5_verify
}

main "$@"
