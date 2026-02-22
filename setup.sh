#!/usr/bin/env bash
set -Eeuo pipefail

# setup.sh — Server-side orchestrator for secure Coolify deployment
# Run directly on the server (after SSH'ing in manually).
#
# Interactive mode:  sudo ./setup.sh
# Non-interactive:   sudo ./setup.sh --server-ip 1.2.3.4 --admin-user ... --yes
# Mixed:             sudo ./setup.sh --server-ip 1.2.3.4  (prompted for the rest)

SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── Inputs (populated by flags or prompts) ──────────────────────────────────

SERVER_IP="${SERVER_IP:-}"
ADMIN_USER="${ADMIN_USER:-}"
PUBKEY_FILE="${PUBKEY_FILE:-}"
TAILSCALE_AUTH_KEY="${TAILSCALE_AUTH_KEY:-}"
DEPLOY_MODE="${DEPLOY_MODE:-}"
DOMAIN="${DOMAIN:-}"
CF_API_TOKEN="${CF_API_TOKEN:-}"
CF_ZONE="${CF_ZONE:-}"
SWAP_SIZE="${SWAP_SIZE:-}"
AUTO_YES="${AUTO_YES:-false}"

# ── Derived at runtime ──────────────────────────────────────────────────────

ADMIN_PUBKEY=""
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

pause_for_operator() {
  if is_true "${AUTO_YES}"; then return 0; fi
  local msg="$1"
  printf '\n  \033[1;33m⏸  %s\033[0m\n' "${msg}"
  printf '  Press Enter when ready...'
  read -r
}

# ── Input helpers ───────────────────────────────────────────────────────────

prompt_value() {
  local var_name="$1" prompt="$2" default="${3:-}" regex="${4:-}"
  local val
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
setup.sh — Server-side orchestrator for secure Coolify deployment

Usage:
  sudo setup.sh [options]

Run this directly on the server. If all required flags are provided,
runs non-interactively. If any are missing, prompts for them.

Required:
  --server-ip <ip>              Server public IPv4 address
  --admin-user <name>           Admin username
  --pubkey-file <path>          SSH public key file (on this server)
  --tailscale-auth-key <key>    Tailscale auth key (tskey-auth-...)
  --domain <fqdn>               Domain name for Coolify
  --cf-api-token <token>        Cloudflare API token

Optional:
  --mode <tunnel|standard>       Deployment mode (default: tunnel)
  --cf-zone <zone>              Cloudflare zone (default: derived from domain)
  --swap-size <size>            Swap size (default: 2G)
  --yes                         Skip confirmation prompts (for automation)
  -h, --help                    Show this help
EOF
}

# ── Argument parsing ────────────────────────────────────────────────────────

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --server-ip)       SERVER_IP="${2:?--server-ip requires a value}"; shift 2 ;;
      --admin-user)      ADMIN_USER="${2:?--admin-user requires a value}"; shift 2 ;;
      --pubkey-file)     PUBKEY_FILE="${2:?--pubkey-file requires a value}"; shift 2 ;;
      --tailscale-auth-key) TAILSCALE_AUTH_KEY="${2:?--tailscale-auth-key requires a value}"; shift 2 ;;
      --mode)            DEPLOY_MODE="${2:?--mode requires a value}"; shift 2 ;;
      --domain)          DOMAIN="${2:?--domain requires a value}"; shift 2 ;;
      --cf-api-token)    CF_API_TOKEN="${2:?--cf-api-token requires a value}"; shift 2 ;;
      --cf-zone)         CF_ZONE="${2:?--cf-zone requires a value}"; shift 2 ;;
      --swap-size)       SWAP_SIZE="${2:?--swap-size requires a value}"; shift 2 ;;
      --yes)             AUTO_YES="true"; shift ;;
      -h|--help)         usage; exit 0 ;;
      *)                 die "Unknown option: $1 (use --help)" ;;
    esac
  done
}

# ── Input collection (flag → prompt fallback) ──────────────────────────────

collect_inputs() {
  [[ -n "${SERVER_IP}" ]]   || prompt_value  SERVER_IP "Server public IP" "" "${IPV4_RE}"
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
  [[ "$(id -u)" -eq 0 ]] || die "This script must be run as root (use sudo)."
  [[ "${SERVER_IP}" =~ ${IPV4_RE} ]]      || die "Invalid server IP: ${SERVER_IP}"
  [[ "${ADMIN_USER}" =~ ${LINUX_USER_RE} ]] || die "Invalid admin username: ${ADMIN_USER}"
  [[ "${ADMIN_USER}" != "root" ]]          || die "Admin user must not be root."

  [[ -f "${PUBKEY_FILE}" ]]                || die "Public key file not found: ${PUBKEY_FILE}"
  ssh-keygen -l -f "${PUBKEY_FILE}" >/dev/null 2>&1 \
    || die "Invalid SSH public key: ${PUBKEY_FILE}"
  ADMIN_PUBKEY="$(cat "${PUBKEY_FILE}")"

  [[ "${TAILSCALE_AUTH_KEY}" == tskey-auth-* ]] \
    || die "Tailscale auth key must start with 'tskey-auth-' (got: ${TAILSCALE_AUTH_KEY:0:12}...)"

  [[ "${DEPLOY_MODE}" == "standard" || "${DEPLOY_MODE}" == "tunnel" ]] \
    || die "Mode must be 'standard' or 'tunnel' (got: ${DEPLOY_MODE})"

  [[ "${DOMAIN}" =~ ${FQDN_RE} ]]         || die "Invalid domain: ${DOMAIN}"
  [[ -n "${CF_API_TOKEN}" ]]               || die "Cloudflare API token is required."
  [[ "${SWAP_SIZE}" =~ ${SWAP_RE} ]]       || die "Invalid swap size: ${SWAP_SIZE} (expected e.g. 2G, 512M)"

  # Verify scripts are present in current directory
  local scripts=(bootstrap_hardening.sh validate_hardening.sh configure_coolify_binding.sh)
  for script in "${scripts[@]}"; do
    [[ -f "${SCRIPT_DIR}/${script}" ]] || die "Required script not found: ${SCRIPT_DIR}/${script}"
  done
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
  local resp
  resp="$(cf_api GET /user/tokens/verify)"
  local status
  status="$(printf '%s' "${resp}" | jq -r '.success // false')"
  [[ "${status}" == "true" ]] || die "Cloudflare API token verification failed: $(printf '%s' "${resp}" | jq -r '.errors[0].message // "unknown"')"
  log "Cloudflare API token verified."
}

cf_get_zone_id() {
  local zone_name="${CF_ZONE:-${DOMAIN#*.}}"
  local dot_count
  dot_count="$(printf '%s' "${DOMAIN}" | tr -cd '.' | wc -c)"
  if [[ "${dot_count}" -le 1 ]]; then
    zone_name="${DOMAIN}"
  fi
  [[ -n "${CF_ZONE}" ]] && zone_name="${CF_ZONE}"

  local resp
  resp="$(cf_api GET "/zones?name=${zone_name}&status=active")"
  CF_ZONE_ID="$(printf '%s' "${resp}" | jq -r '.result[0].id // empty')"
  [[ -n "${CF_ZONE_ID}" ]] || die "Cloudflare zone not found for '${zone_name}'. Check domain or use --cf-zone."
  CF_ZONE_NAME="${zone_name}"
  log "Cloudflare zone ID: ${CF_ZONE_ID} (${zone_name})"
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

verify_docker_user_gate_local() {
  local gate_label="$1"
  local gate_d_inactive_msg="Gate D failed: docker-user-hardening.service is not active."

  if systemctl is-active --quiet docker-user-hardening.service; then
    pass "${gate_label}: docker-user-hardening.service is active"
  else
    fail "${gate_label}: docker-user-hardening.service is not active"
    die "${gate_d_inactive_msg}"
  fi

  local iptables_out
  iptables_out="$(iptables -S DOCKER-USER 2>/dev/null)" || true
  if printf '%s' "${iptables_out}" | grep -q "coolify-hardening"; then
    pass "${gate_label}: DOCKER-USER hardening rules active"
  else
    fail "${gate_label}: DOCKER-USER hardening rules not found"
    die "${gate_label} failed. Check: systemctl status docker-user-hardening.service"
  fi
}

reconcile_docker_daemon_local() {
  log "Reconciling Docker daemon settings after Coolify install..."
  # Hardening owns: log-driver, log-opts, live-restore. Coolify may add: default-address-pools.
  # Using json-file driver to match Coolify's expectation for compatibility.
  local daemon_json="/etc/docker/daemon.json"
  local tmp
  tmp="$(mktemp)"

  # Drift detection: warn if hardening keys were changed (e.g., by Coolify update)
  if [[ -f "${daemon_json}" ]]; then
    local current_driver current_live_restore
    current_driver="$(jq -r '.["log-driver"] // ""' "${daemon_json}" 2>/dev/null || true)"
    if [[ "${current_driver}" != "" && "${current_driver}" != "json-file" ]]; then
      warn "Docker log-driver drift detected (was '${current_driver}', expected 'json-file'). Reconciling..."
    fi
    current_live_restore="$(jq -r '.["live-restore"] // ""' "${daemon_json}" 2>/dev/null || true)"
    if [[ "${current_live_restore}" != "" && "${current_live_restore}" != "true" ]]; then
      warn "Docker live-restore drift detected (was '${current_live_restore}', expected 'true'). Reconciling..."
    fi
  fi

  if [[ -f "${daemon_json}" ]]; then
    jq '. + {"log-driver":"json-file","log-opts":((.["log-opts"] // {}) + {"max-size":"10m","max-file":"3"}),"live-restore":true}' "${daemon_json}" > "${tmp}"
  else
    jq -n '{"log-driver":"json-file","log-opts":{"max-size":"10m","max-file":"3"},"live-restore":true}' > "${tmp}"
  fi

  if [[ -f "${daemon_json}" ]] && cmp -s "${tmp}" "${daemon_json}"; then
    rm -f "${tmp}"
    pass "Docker daemon settings already match hardening policy"
    return 0
  fi

  if [[ -f "${daemon_json}" ]]; then
    cp -a "${daemon_json}" "${daemon_json}.bak.$(date +%s)"
  fi

  cat "${tmp}" > "${daemon_json}"
  chmod 0644 "${daemon_json}"
  rm -f "${tmp}"
  systemctl restart docker
  pass "Docker daemon hardening reconciled (json-file log rotation + live-restore)"
}

run_final_validation_gate_local() {
  log "Running final validate_hardening.sh..."
  local validate_json
  validate_json="$("${SCRIPT_DIR}/validate_hardening.sh" --json 2>/dev/null)" || true
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
  local required_cmds=(curl jq ssh-keygen openssl)
  for cmd in "${required_cmds[@]}"; do
    command -v "${cmd}" >/dev/null 2>&1 || die "Required command not found: ${cmd}. Install it first."
  done
  pass "Required tools present"

  # Validate pubkey
  ssh-keygen -l -f "${PUBKEY_FILE}" >/dev/null 2>&1 || die "Invalid SSH public key file: ${PUBKEY_FILE}"
  pass "SSH public key valid: ${PUBKEY_FILE}"

  # Verify Cloudflare token
  cf_verify_token
  cf_get_zone_id
  cf_get_account_id  # always fetch — needed for tunnel (default mode)
  pass "Cloudflare API verified (zone: ${CF_ZONE_ID})"
}

# ── Phase 1: Harden ────────────────────────────────────────────────────────

phase1_harden() {
  step "1/5" "Harden server"

  local tunnel_flag="false"
  [[ "${DEPLOY_MODE}" == "tunnel" ]] && tunnel_flag="true"

  # Write env file (avoids quoting issues with pubkey)
  cat > /root/deploy.env <<EOF
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
  chmod 600 /root/deploy.env
  pass "Environment file written"

  # Run hardening
  log "Running bootstrap_hardening.sh (this may take a few minutes)..."
  "${SCRIPT_DIR}/bootstrap_hardening.sh" --env-file /root/deploy.env --install-tailscale --force \
    || die "bootstrap_hardening.sh failed. Check: /var/log/bootstrap-hardening.log"
  pass "Hardening completed"

  # Capture Tailscale IP
  TS_IP="$(tailscale ip -4 2>/dev/null | tr -d '[:space:]')"
  [[ -n "${TS_IP}" ]] || die "Failed to get Tailscale IP."
  pass "Server Tailscale IP: ${TS_IP}"

  # Clean up sensitive env file
  rm -f /root/deploy.env
}

# ── Phase 2: Gate checks ───────────────────────────────────────────────────

phase2_gates() {
  step "2/5" "Gate checks"

  # Gate A: Operator verifies SSH from laptop
  pause_for_operator "From your LAPTOP, verify SSH: ssh ${ADMIN_USER}@${TS_IP} (Tailscale IP)"

  # Gate B: Verify admin user is functional locally
  local admin_home
  admin_home="$(getent passwd "${ADMIN_USER}" | cut -d: -f6 2>/dev/null)" || true
  if [[ -n "${admin_home}" ]] && [[ -d "${admin_home}/.ssh" ]]; then
    pass "Gate B: Admin user ${ADMIN_USER} exists with SSH dir"
  else
    fail "Gate B: Admin user ${ADMIN_USER} home or .ssh not found"
    die "Gate B failed."
  fi

  # Gate C: Validation passes
  log "Gate C: Running validate_hardening.sh..."
  local validate_json
  validate_json="$("${SCRIPT_DIR}/validate_hardening.sh" --json 2>/dev/null)" || true
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

  # Install Docker
  log "Installing Docker..."
  curl -fsSL https://get.docker.com | sh \
    || die "Docker installation failed."
  pass "Docker installed"

  # Start DOCKER-USER hardening service
  systemctl start docker-user-hardening.service \
    || die "Failed to start docker-user-hardening.service"

  # Gate D: Verify DOCKER-USER rules
  verify_docker_user_gate_local "Gate D"

  # Install Coolify
  log "Installing Coolify (this may take a few minutes)..."
  curl -fsSL https://cdn.coollabs.io/coolify/install.sh | bash \
    || die "Coolify installation failed."
  pass "Coolify installed"

  # Coolify installer manages daemon.json; re-apply hardening settings while preserving its keys.
  reconcile_docker_daemon_local

  # Docker restart can flush DOCKER-USER runtime rules; re-apply and verify.
  systemctl restart docker-user-hardening.service \
    || die "Failed to restart docker-user-hardening.service after Docker daemon reconciliation."
  verify_docker_user_gate_local "Gate D (post-Coolify)"
}

# ── Phase 4: Binding + DNS ─────────────────────────────────────────────────

phase4_binding_dns() {
  step "4/5" "Configure dashboard binding & DNS"

  # Run configure_coolify_binding.sh directly
  log "Binding Coolify dashboard to Tailscale IP..."
  "${SCRIPT_DIR}/configure_coolify_binding.sh" --tailscale-ip "${TS_IP}" \
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

    # Install cloudflared
    log "Installing cloudflared..."
    apt-get update -qq && apt-get install -y -qq cloudflared 2>/dev/null \
      || {
        log "Trying Cloudflare repository..."
        curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg \
          | tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
        echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared $(lsb_release -cs) main" \
          | tee /etc/apt/sources.list.d/cloudflared.list
        apt-get update -qq && apt-get install -y -qq cloudflared \
          || die "Failed to install cloudflared"
      }
    pass "cloudflared installed"

    # Write tunnel credentials
    local creds_json
    creds_json="$(jq -n --arg id "${TUNNEL_ID}" --arg secret "${TUNNEL_SECRET}" --arg account "${CF_ACCOUNT_ID}" \
      '{AccountTag:$account,TunnelID:$id,TunnelSecret:$secret}')"
    mkdir -p /etc/cloudflared
    printf '%s' "${creds_json}" > "/etc/cloudflared/${TUNNEL_ID}.json"
    chmod 600 "/etc/cloudflared/${TUNNEL_ID}.json"

    # Write tunnel config with wildcard ingress for multi-app support
    local wildcard_hostname="*.${CF_ZONE_NAME}"
    cat > /etc/cloudflared/config.yml <<EOF
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
    cloudflared service install 2>/dev/null || true
    systemctl enable --now cloudflared \
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

  # Gate E: Operator verifies from laptop
  pause_for_operator "From your LAPTOP, verify: curl http://${TS_IP}:8000 should work; curl http://${SERVER_IP}:8000 should NOT"

  # Final validation run
  run_final_validation_gate_local

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
  phase1_harden
  phase2_gates
  phase3_docker_coolify
  phase4_binding_dns
  phase5_verify
}

main "$@"
