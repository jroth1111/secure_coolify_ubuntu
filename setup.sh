#!/usr/bin/env bash
if [[ -z "${BASH_VERSINFO:-}" || "${BASH_VERSINFO[0]}" -lt 4 ]]; then
  printf 'FATAL: %s requires Bash 4+ (found %s). On macOS: brew install bash, then run with /opt/homebrew/bin/bash %s ...\n' \
    "$(basename "$0")" "${BASH_VERSION:-unknown}" "$(basename "$0")" >&2
  exit 1
fi
set -Eeuo pipefail

# setup.sh — Server-side orchestrator for secure Coolify deployment
# Run directly on the server (after SSH'ing in manually).
#
# Interactive mode:  sudo ./setup.sh
# Non-interactive:   sudo ./setup.sh --server-ip 1.2.3.4 --admin-user ... --yes
# Mixed:             sudo ./setup.sh --server-ip 1.2.3.4  (prompted for the rest)

SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/coolify-common.sh
source "${SCRIPT_DIR}/lib/coolify-common.sh"

# ── Inputs (populated by flags or prompts) ──────────────────────────────────

SERVER_IP="${SERVER_IP:-}"
ADMIN_USER="${ADMIN_USER:-}"
PUBKEY_FILE="${PUBKEY_FILE:-}"
TAILSCALE_AUTH_KEY="${TAILSCALE_AUTH_KEY:-}"
DEPLOY_MODE="${DEPLOY_MODE:-}"
DOMAIN="${DOMAIN:-}"
CF_API_TOKEN="${CF_API_TOKEN:-}"
CF_API_TOKEN_FILE="${CF_API_TOKEN_FILE:-}"
CF_TUNNEL_API_TOKEN="${CF_TUNNEL_API_TOKEN:-}"
CF_TUNNEL_API_TOKEN_FILE="${CF_TUNNEL_API_TOKEN_FILE:-}"
CF_ZONE="${CF_ZONE:-}"
CF_ZONE_ID="${CF_ZONE_ID:-}"
CF_ACCOUNT_ID="${CF_ACCOUNT_ID:-}"
APP_DOMAIN_MODE="${APP_DOMAIN_MODE:-}"
SWAP_SIZE="${SWAP_SIZE:-}"
SERVER_TIMEZONE="${SERVER_TIMEZONE:-}"
TAILSCALE_DIRECT_WAN="${TAILSCALE_DIRECT_WAN:-false}"
AUTO_YES="${AUTO_YES:-false}"
PREFLIGHT_ONLY="${PREFLIGHT_ONLY:-false}"

# ── Derived at runtime ──────────────────────────────────────────────────────

ADMIN_PUBKEY=""
TS_IP=""
CF_ZONE_NAME=""
APP_DOMAIN=""
TUNNEL_ID=""
TUNNEL_SECRET=""
PENDING_DEPLOY_ENV_FILE=""

setup_exit_trap() {
  local exit_code=$?
  if [[ -n "${PENDING_DEPLOY_ENV_FILE}" ]]; then
    rm -f "${PENDING_DEPLOY_ENV_FILE}" 2>/dev/null || true
    PENDING_DEPLOY_ENV_FILE=""
  fi
  run_report_finalize "${exit_code}"
}

pause_for_operator() {
  if is_true "${AUTO_YES}"; then return 0; fi
  local msg="$1"
  printf '\n  \033[1;33m⏸  %s\033[0m\n' "${msg}"
  printf '  Press Enter when ready...'
  read -r
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
  --tailscale-auth-key <key>    Required unless --preflight-only
  --domain <fqdn>               Domain name for Coolify
  Cloudflare API token          Provide via CF_API_TOKEN, --cf-api-token-file, or prompt

Optional:
  --cf-api-token-file <path>    File containing Cloudflare API token
  --cf-tunnel-api-token-file <path>
                                File containing Cloudflare tunnel API token (optional; defaults to API token)
  --mode <tunnel|standard>       Deployment mode (default: tunnel)
  --app-domain-mode <vps|apex>  App subdomain scope: vps=appname.DOMAIN, apex=appname.ZONE (default: apex)
  --cf-zone <zone>              Cloudflare zone (default: derived from domain)
  --cf-zone-id <id>             Cloudflare zone ID override (32-char hex)
  --cf-account-id <id>          Cloudflare account ID override (32-char hex)
  --swap-size <size>            Swap size (default: 2G)
  --server-timezone <IANA>      Server timezone (for example: Australia/Melbourne, UTC)
  --tailscale-direct-wan        Allow WAN UDP 41641 for direct Tailscale paths (optional optimization)
  --no-tailscale-direct-wan     Keep WAN UDP 41641 closed (default; DERP fallback remains available)
  --preflight-only              Run local/Cloudflare preflight checks only, then exit
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
      --cf-api-token)
        die "--cf-api-token is removed for security. Use CF_API_TOKEN env var or --cf-api-token-file."
        ;;
      --cf-tunnel-api-token)
        die "--cf-tunnel-api-token is removed for security. Use CF_TUNNEL_API_TOKEN env var or --cf-tunnel-api-token-file."
        ;;
      --cf-api-token-file) CF_API_TOKEN_FILE="${2:?--cf-api-token-file requires a value}"; shift 2 ;;
      --cf-tunnel-api-token-file) CF_TUNNEL_API_TOKEN_FILE="${2:?--cf-tunnel-api-token-file requires a value}"; shift 2 ;;
      --cf-zone)         CF_ZONE="${2:?--cf-zone requires a value}"; shift 2 ;;
      --cf-zone-id)      CF_ZONE_ID="${2:?--cf-zone-id requires a value}"; shift 2 ;;
      --cf-account-id)   CF_ACCOUNT_ID="${2:?--cf-account-id requires a value}"; shift 2 ;;
      --app-domain-mode) APP_DOMAIN_MODE="${2:?--app-domain-mode requires a value}"; shift 2 ;;
      --swap-size)       SWAP_SIZE="${2:?--swap-size requires a value}"; shift 2 ;;
      --server-timezone|--timezone) SERVER_TIMEZONE="${2:?$1 requires a value}"; shift 2 ;;
      --tailscale-direct-wan) TAILSCALE_DIRECT_WAN="true"; shift ;;
      --no-tailscale-direct-wan) TAILSCALE_DIRECT_WAN="false"; shift ;;
      --preflight-only)  PREFLIGHT_ONLY="true"; shift ;;
      --yes)             AUTO_YES="true"; shift ;;
      -h|--help)         usage; exit 0 ;;
      *)                 die "Unknown option: $1 (use --help)" ;;
    esac
  done
}

# ── Input collection (flag → prompt fallback) ──────────────────────────────

collect_inputs() {
  if is_true "${PREFLIGHT_ONLY}" && [[ -z "${TAILSCALE_AUTH_KEY}" ]]; then
    TAILSCALE_AUTH_KEY="(not-needed)"
  fi
  collect_common_inputs
}

# ── Input validation ───────────────────────────────────────────────────────

validate_inputs() {
  finalize_cloudflare_tokens

  if ! is_true "${PREFLIGHT_ONLY}"; then
    [[ "$(id -u)" -eq 0 ]] || die "This script must be run as root (use sudo)."
  fi
  [[ "${SERVER_IP}" =~ ${IPV4_RE} ]]      || die "Invalid server IP: ${SERVER_IP}"
  [[ "${ADMIN_USER}" =~ ${LINUX_USER_RE} ]] || die "Invalid admin username: ${ADMIN_USER}"
  [[ "${ADMIN_USER}" != "root" ]]          || die "Admin user must not be root."

  [[ -f "${PUBKEY_FILE}" ]]                || die "Public key file not found: ${PUBKEY_FILE}"
  ssh-keygen -l -f "${PUBKEY_FILE}" >/dev/null 2>&1 \
    || die "Invalid SSH public key: ${PUBKEY_FILE}"
  ADMIN_PUBKEY="$(cat "${PUBKEY_FILE}")"

  if ! is_true "${PREFLIGHT_ONLY}"; then
    [[ "${TAILSCALE_AUTH_KEY}" == tskey-auth-* ]] \
      || die "Tailscale auth key must start with 'tskey-auth-' (got: ${TAILSCALE_AUTH_KEY:0:12}...)"
  fi

  [[ "${DEPLOY_MODE}" == "standard" || "${DEPLOY_MODE}" == "tunnel" ]] \
    || die "Mode must be 'standard' or 'tunnel' (got: ${DEPLOY_MODE})"

  [[ "${APP_DOMAIN_MODE}" == "vps" || "${APP_DOMAIN_MODE}" == "apex" ]] \
    || die "App domain mode must be 'vps' or 'apex' (got: ${APP_DOMAIN_MODE})"

  [[ "${DOMAIN}" =~ ${FQDN_RE} ]]         || die "Invalid domain: ${DOMAIN}"
  [[ -n "${CF_API_TOKEN}" ]]               || die "Cloudflare API token is required."
  [[ -z "${CF_ZONE_ID}" || "${CF_ZONE_ID}" =~ ${CF_ID_RE} ]] \
    || die "Invalid --cf-zone-id: ${CF_ZONE_ID} (expected 32-char hex)"
  [[ -z "${CF_ACCOUNT_ID}" || "${CF_ACCOUNT_ID}" =~ ${CF_ID_RE} ]] \
    || die "Invalid --cf-account-id: ${CF_ACCOUNT_ID} (expected 32-char hex)"
  [[ "${SWAP_SIZE}" =~ ${SWAP_RE} ]]       || die "Invalid swap size: ${SWAP_SIZE} (expected e.g. 2G, 512M)"
  [[ "${SERVER_TIMEZONE}" =~ ${TIMEZONE_RE} ]] \
    || die "Invalid server timezone: ${SERVER_TIMEZONE} (expected IANA name like Australia/Melbourne or UTC)"
  case "${TAILSCALE_DIRECT_WAN,,}" in
    true|false|1|0|yes|no|y|n|on|off) ;;
    *) die "TAILSCALE_DIRECT_WAN must be true/false (got: ${TAILSCALE_DIRECT_WAN})" ;;
  esac

  # Verify scripts are present in current directory
  local scripts=(bootstrap_hardening.sh validate_hardening.sh configure_coolify_binding.sh)
  for script in "${scripts[@]}"; do
    [[ -f "${SCRIPT_DIR}/${script}" ]] || die "Required script not found: ${SCRIPT_DIR}/${script}"
  done
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
  # Hardening owns: log-driver, log-opts, live-restore, default-ipc-mode, storage-driver.
  # Using json-file driver to match Coolify's expectation for compatibility.
  coolify_reconcile_docker_daemon_script | bash -s \
    || die "Failed to reconcile Docker daemon hardening settings."
  pass "Docker daemon hardening reconciled (json-file log rotation + live-restore)"
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
  cf_verify_dns_write_token
  cf_get_account_id  # always fetch — needed for tunnel (default mode)
  cf_verify_tunnel_token
  resolve_app_domain
  pass "Cloudflare API verified (zone: ${CF_ZONE_ID})"
}

# ── Phase 1: Harden ────────────────────────────────────────────────────────

phase1_harden() {
  step "1/5" "Harden server"
  local deploy_env_file="${DEPLOY_ENV_FILE:-/root/deploy.env}"
  PENDING_DEPLOY_ENV_FILE="${deploy_env_file}"

  local tunnel_flag="false"
  [[ "${DEPLOY_MODE}" == "tunnel" ]] && tunnel_flag="true"

  # Write env file (avoids quoting issues with pubkey)
  cat > "${deploy_env_file}" <<EOF
ADMIN_USER=${ADMIN_USER}
ADMIN_PUBKEY="${ADMIN_PUBKEY}"
TAILSCALE_CIDR=100.64.0.0/10
SSH_PORT=22
TUNNEL_MODE=${tunnel_flag}
SWAP_SIZE=${SWAP_SIZE}
TIMEZONE=${SERVER_TIMEZONE}
INSTALL_TAILSCALE=true
TAILSCALE_AUTH_KEY=${TAILSCALE_AUTH_KEY}
TAILSCALE_DIRECT_WAN=${TAILSCALE_DIRECT_WAN}
BIND_DASHBOARD_TO_TAILSCALE=false
EOF
  chmod 600 "${deploy_env_file}"
  pass "Environment file written"

  # Run hardening
  log "Running bootstrap_hardening.sh (this may take a few minutes)..."
  if ! run_with_heartbeat \
    "bootstrap_hardening.sh (local server)" \
    "${SCRIPT_DIR}/bootstrap_hardening.sh" --env-file "${deploy_env_file}" --install-tailscale --force; then
    warn "bootstrap_hardening.sh failed. Last 50 lines from /var/log/bootstrap-hardening.log:"
    tail -n 50 /var/log/bootstrap-hardening.log 2>/dev/null || true
    die "bootstrap_hardening.sh failed. Check: /var/log/bootstrap-hardening.log"
  fi
  pass "Hardening completed"

  # Capture Tailscale IP
  TS_IP="$(tailscale ip -4 2>/dev/null | tr -d '[:space:]')"
  [[ -n "${TS_IP}" ]] || die "Failed to get Tailscale IP."
  pass "Server Tailscale IP: ${TS_IP}"

  # Clean up sensitive env file
  rm -f "${deploy_env_file}"
  PENDING_DEPLOY_ENV_FILE=""
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

  if [[ -f /run/reboot-required ]]; then
    local reboot_pkgs
    reboot_pkgs="$(tr '\n' ',' < /run/reboot-required.pkgs 2>/dev/null | sed 's/,$//' || true)"
    fail "Gate B.5: Reboot required before validation (${reboot_pkgs:-unknown packages})"
    die "Reboot the server, then rerun setup.sh to continue from a clean post-upgrade state."
  fi

  # Gate C: Validation passes
  # Resume safety: if Docker is already present from a prior partial run, re-apply
  # hardening-owned Docker settings before Gate C validation.
  if docker version >/dev/null 2>&1; then
    log "Gate C pre-check: Docker detected; reconciling daemon and bridge-SSH rules..."
    reconcile_docker_daemon_local
    systemctl enable --now docker-user-hardening.service 2>/dev/null || true
    systemctl start docker-ssh-cidr-sync.service 2>/dev/null || true
  fi

  log "Gate C: Running validate_hardening.sh..."
  local validate_json gate_c_fail attempt max_attempts=6 delay=10
  for (( attempt=1; attempt<=max_attempts; attempt++ )); do
    validate_json="$("${SCRIPT_DIR}/validate_hardening.sh" --json --gate-c 2>/dev/null)" || true
    gate_c_fail="$(jq -r '.fail // 999' 2>/dev/null <<< "${validate_json:-}" || echo "999")"
    if [[ "${gate_c_fail}" == "0" ]]; then
      report_validation_result "Gate C" "${validate_json}" \
        "Gate C failed. Fix validation failures before continuing."
      break
    fi
    if (( attempt < max_attempts )) \
      && jq -e '.checks | [ .[] | select(.status=="FAIL") | .check ] as $fails | ($fails|length)>0 and all($fails[]; .=="timesync: NTPSynchronized")' \
        >/dev/null 2>&1 <<< "${validate_json}"; then
      log "  Gate C transient failure (timesync not yet synchronized); retrying in ${delay}s (${attempt}/${max_attempts})..."
      sleep "${delay}"
      continue
    fi
    report_validation_result "Gate C" "${validate_json}" \
      "Gate C failed. Fix validation failures before continuing."
  done
}

# ── Phase 3: Docker + Coolify ──────────────────────────────────────────────

phase3_docker_coolify() {
  phase3_has_docker() { docker version >/dev/null 2>&1; }
  phase3_install_docker() { coolify_install_docker_engine_script | bash -s; }
  phase3_start_docker_user() { systemctl enable --now docker-user-hardening.service; }
  phase3_verify_docker_user() { verify_docker_user_gate_local "$1"; }
  phase3_has_coolify_env() { [[ -f /data/coolify/source/.env ]] && docker inspect coolify >/dev/null 2>&1; }
  phase3_install_coolify() { coolify_install_coolify_script | bash -s; }
  phase3_reconcile_docker_daemon() { reconcile_docker_daemon_local; }
  phase3_restart_docker_user() { systemctl restart docker-user-hardening.service; }
  phase3_add_coolify_root_key() { coolify_add_coolify_root_key_script | bash -s; }
  phase3_fix_host_docker_internal() { coolify_fix_host_docker_internal_script | bash -s; }
  phase3_sync_docker_ssh_cidrs() { systemctl start docker-ssh-cidr-sync.service; }

  # Gate D: Verify DOCKER-USER rules
  coolify_phase3_docker_coolify_shared \
    phase3_has_docker \
    phase3_install_docker \
    phase3_start_docker_user \
    phase3_verify_docker_user \
    phase3_has_coolify_env \
    phase3_install_coolify \
    phase3_reconcile_docker_daemon \
    phase3_restart_docker_user \
    phase3_add_coolify_root_key \
    phase3_fix_host_docker_internal \
    phase3_sync_docker_ssh_cidrs
}

# ── Phase 4: Binding + DNS ─────────────────────────────────────────────────

phase4_binding_dns() {
  phase4_coolify_env_exists() { [[ -f /data/coolify/source/.env ]]; }
  phase4_configure_binding() { "${SCRIPT_DIR}/configure_coolify_binding.sh" --tailscale-ip "${TS_IP}"; }
  phase4_mark_binding_state() {
    {
      coolify_mark_bind_dashboard_state_script
      coolify_install_binding_guard_script
    } | bash -s
  }
  phase4_set_wildcard_domain() { APP_DOMAIN="${APP_DOMAIN}" coolify_set_wildcard_domain_script | bash -s; }
  phase4_reconcile_pusher_env() {
    DEPLOY_MODE="${DEPLOY_MODE}" TS_IP="${TS_IP}" DOMAIN="${DOMAIN}" coolify_reconcile_pusher_env_script | bash -s
  }
  phase4_install_cloudflared() { coolify_install_cloudflared_script | bash -s; }
  phase4_configure_cloudflared() {
    TUNNEL_ID="${TUNNEL_ID}" \
    TUNNEL_SECRET="${TUNNEL_SECRET}" \
    CF_ACCOUNT_ID="${CF_ACCOUNT_ID}" \
    DOMAIN="${DOMAIN}" \
    APP_DOMAIN="${APP_DOMAIN}" \
    CF_ZONE_NAME="${CF_ZONE_NAME}" \
      coolify_configure_cloudflared_script | bash -s
  }
  phase4_stop_cloudflared() { systemctl stop cloudflared 2>/dev/null || true; }
  phase4_configure_private_routes() {
    DOMAIN="${DOMAIN}" PRIVATE_TLS_RESOLVER="privatedns" coolify_configure_private_dashboard_routes_script | bash -s
  }
  phase4_configure_private_tls() {
    CF_DNS_API_TOKEN="${CF_API_TOKEN}" CF_ZONE_NAME="${CF_ZONE_NAME}" PRIVATE_TLS_RESOLVER="privatedns" \
      coolify_configure_private_tls_dns_script | bash -s
  }
  phase4_remove_private_routes() {
    coolify_remove_private_dashboard_routes_script | bash -s
  }

  # Contract anchors kept for tests/docs:
  # sed '/^PUSHER_HOST=/d; /^PUSHER_PORT=/d; /^PUSHER_SCHEME=/d'
  # PUSHER_HOST=ws.${DOMAIN}
  # coolify-private-dashboard.yaml
  # ws.${DOMAIN}
  coolify_phase4_binding_dns_shared \
    phase4_coolify_env_exists \
    phase4_configure_binding \
    phase4_mark_binding_state \
    phase4_set_wildcard_domain \
    phase4_reconcile_pusher_env \
    phase4_install_cloudflared \
    phase4_configure_cloudflared \
    phase4_stop_cloudflared \
    phase4_configure_private_routes \
    phase4_configure_private_tls \
    phase4_remove_private_routes
}

# ── Phase 5: Verification ─────────────────────────────────────────────────

phase5_fetch_validate_json() { "${SCRIPT_DIR}/validate_hardening.sh" --json; }

phase5_verify() {
  # Contract anchors kept for docs/consistency checks:
  # Gate E: Operator verifies from laptop
  # Running final validate_hardening.sh...
  # setup.sh runs on the server itself; public-IP reachability checks are confirmed
  # from an operator laptop in coolify_phase5_verify_shared (public_probe_mode=operator).
  coolify_phase5_verify_shared phase5_fetch_validate_json operator pause_for_operator
}

# ── Main ────────────────────────────────────────────────────────────────────

main() {
  run_report_init "${SCRIPT_NAME}"
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
  log "  App scope: ${APP_DOMAIN_MODE}"
  log "  Swap:      ${SWAP_SIZE}"
  log "  Timezone:  ${SERVER_TIMEZONE}"
  log "  Local TZ:  $(local_tz_offset) (logs use UTC)"
  is_true "${PREFLIGHT_ONLY}" && log "  Mode:      preflight-only (no server changes)"
  [[ "${CF_TUNNEL_API_TOKEN}" != "${CF_API_TOKEN}" ]] && log "  CF tunnel token: custom"
  confirm "Proceed with deployment?"

  preflight
  if is_true "${PREFLIGHT_ONLY}"; then
    pass "Preflight-only checks completed. Exiting without deployment changes."
    return 0
  fi
  phase1_harden
  phase2_gates
  phase3_docker_coolify
  phase4_binding_dns
  phase5_verify
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  trap 'setup_exit_trap' EXIT
  main "$@"
fi
