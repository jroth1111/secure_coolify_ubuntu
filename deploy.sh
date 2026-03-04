#!/usr/bin/env bash
set -Eeuo pipefail

# deploy.sh — Laptop-side orchestrator for secure Coolify deployment
# Runs on the operator's machine; SSHes into the remote server.
#
# Interactive mode:  ./deploy.sh
# Non-interactive:   ./deploy.sh --server-ip 1.2.3.4 --root-pass-file /path/root.pass --yes
# Mixed:             ./deploy.sh --server-ip 1.2.3.4  (prompted for the rest)

SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=lib/coolify-common.sh
source "${SCRIPT_DIR}/lib/coolify-common.sh"

# ── Inputs (populated by flags or prompts) ──────────────────────────────────

SERVER_IP="${SERVER_IP:-}"
ROOT_PASS="${ROOT_PASS:-}"
ROOT_PASS_FILE="${ROOT_PASS_FILE:-}"
ROOT_PASS_RUNTIME_FILE=""
ADMIN_USER="${ADMIN_USER:-}"
PUBKEY_FILE="${PUBKEY_FILE:-}"
TAILSCALE_AUTH_KEY="${TAILSCALE_AUTH_KEY:-}"
DEPLOY_MODE="${DEPLOY_MODE:-}"
DOMAIN="${DOMAIN:-}"
CF_API_TOKEN="${CF_API_TOKEN:-}"
CF_ZONE="${CF_ZONE:-}"
APP_DOMAIN_MODE="${APP_DOMAIN_MODE:-}"
SWAP_SIZE="${SWAP_SIZE:-}"
TAILSCALE_DIRECT_WAN="${TAILSCALE_DIRECT_WAN:-false}"
AUTO_YES="${AUTO_YES:-false}"
SKIP_HARDEN="${SKIP_HARDEN:-false}"  # set via --ts-ip to resume after partial harden

# ── Derived at runtime ──────────────────────────────────────────────────────

ADMIN_PUBKEY=""
PRIVATE_KEY=""
TS_IP=""
CF_ZONE_ID=""
CF_ZONE_NAME=""
APP_DOMAIN=""
CF_ACCOUNT_ID=""
TUNNEL_ID=""
TUNNEL_SECRET=""

# ── SSH options ─────────────────────────────────────────────────────────────

# Temp known-hosts files are created in init_ssh_options() (called from main)
# so sourcing this file for tests doesn't trigger mktemp/trap side-effects.
DEPLOY_KNOWN_HOSTS=""
ADMIN_KNOWN_HOSTS=""
declare -a SSH_OPTS=()
declare -a ROOT_SSH_OPTS=()

cleanup_temp_files() {
  rm -f "${DEPLOY_KNOWN_HOSTS:-}" "${ADMIN_KNOWN_HOSTS:-}" "${ROOT_PASS_RUNTIME_FILE:-}"
}

init_ssh_options() {
  # Use accept-new: accept on first connect, reject changed keys (OpenSSH 7.6+).
  DEPLOY_KNOWN_HOSTS="$(mktemp)" || die "Failed to create temp file for deploy known hosts"
  ADMIN_KNOWN_HOSTS="$(mktemp)" || die "Failed to create temp file for admin known hosts"
  trap 'cleanup_temp_files' EXIT

  SSH_OPTS=(
    -o StrictHostKeyChecking=accept-new
    -o "UserKnownHostsFile=${ADMIN_KNOWN_HOSTS}"
    -o ConnectTimeout=10
    -o LogLevel=ERROR
  )
  # Root SSH uses password auth; PreferredAuthentications ensures sshpass works even when server
  # advertises publickey first (macOS OpenSSH skips password challenge otherwise).
  ROOT_SSH_OPTS=(
    -o StrictHostKeyChecking=accept-new
    -o "UserKnownHostsFile=${DEPLOY_KNOWN_HOSTS}"
    -o ConnectTimeout=10
    -o LogLevel=ERROR
    -o PreferredAuthentications=keyboard-interactive,password
  )
}

init_root_password_auth() {
  if is_true "${SKIP_HARDEN}"; then
    return 0
  fi
  [[ -n "${ROOT_PASS}" ]] || die "Root password is required for phase 1."
  ROOT_PASS_RUNTIME_FILE="$(mktemp)" || die "Failed to create temp file for root password"
  chmod 600 "${ROOT_PASS_RUNTIME_FILE}"
  printf '%s' "${ROOT_PASS}" > "${ROOT_PASS_RUNTIME_FILE}"
  ROOT_PASS=""
}

# ── Usage ───────────────────────────────────────────────────────────────────

usage() {
  cat <<'EOF'
deploy.sh — Laptop-side orchestrator for secure Coolify deployment
Run this on your LOCAL MACHINE (laptop/workstation), not on the server.

Usage:
  deploy.sh [options]

If all required flags are provided, runs non-interactively.
If any are missing, prompts for them (mixed mode supported).

Required:
  --server-ip <ip>              Server public IPv4 address
  Root password                 Provide via --root-pass-file or interactive prompt
  --tailscale-auth-key <key>    Tailscale auth key (tskey-auth-...)
  --domain <fqdn>               Domain name for Coolify
  --cf-api-token <token>        Cloudflare API token

Optional:
  --admin-user <name>           Admin username (default: coolifyadmin)
  --root-pass-file <path>       Read root password from file (recommended for automation)
  --pubkey-file <path>          SSH public key file (default: ~/.ssh/id_ed25519.pub)
  --mode <tunnel|standard>       Deployment mode (default: tunnel)
  --app-domain-mode <vps|apex>  App subdomain scope: vps=appname.DOMAIN, apex=appname.ZONE (default: apex)
  --cf-zone <zone>              Cloudflare zone (default: derived from domain)
  --swap-size <size>            Swap size (default: 2G)
  --tailscale-direct-wan        Allow WAN UDP 41641 for direct Tailscale paths (optional optimization)
  --no-tailscale-direct-wan     Keep WAN UDP 41641 closed (default; DERP fallback remains available)
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
      --root-pass)
        die "--root-pass is disabled for security (CLI args leak to process list/history). Use --root-pass-file or interactive prompt."
        ;;
      --root-pass-file)  ROOT_PASS_FILE="${2:?--root-pass-file requires a value}"; shift 2 ;;
      --admin-user)      ADMIN_USER="${2:?--admin-user requires a value}"; shift 2 ;;
      --pubkey-file)     PUBKEY_FILE="${2:?--pubkey-file requires a value}"; shift 2 ;;
      --tailscale-auth-key) TAILSCALE_AUTH_KEY="${2:?--tailscale-auth-key requires a value}"; shift 2 ;;
      --mode)            DEPLOY_MODE="${2:?--mode requires a value}"; shift 2 ;;
      --domain)          DOMAIN="${2:?--domain requires a value}"; shift 2 ;;
      --cf-api-token)    CF_API_TOKEN="${2:?--cf-api-token requires a value}"; shift 2 ;;
      --cf-zone)         CF_ZONE="${2:?--cf-zone requires a value}"; shift 2 ;;
      --app-domain-mode) APP_DOMAIN_MODE="${2:?--app-domain-mode requires a value}"; shift 2 ;;
      --swap-size)       SWAP_SIZE="${2:?--swap-size requires a value}"; shift 2 ;;
      --tailscale-direct-wan) TAILSCALE_DIRECT_WAN="true"; shift ;;
      --no-tailscale-direct-wan) TAILSCALE_DIRECT_WAN="false"; shift ;;
      --yes)             AUTO_YES="true"; shift ;;
      --ts-ip)           TS_IP="${2:?--ts-ip requires a value}"; SKIP_HARDEN="true"; shift 2 ;;
      -h|--help)         usage; exit 0 ;;
      *)                 die "Unknown option: $1 (use --help)" ;;
    esac
  done
}

# ── Input collection (flag → prompt fallback) ──────────────────────────────

collect_inputs() {
  # When hardening is being skipped (--ts-ip), tailscale auth key is not needed.
  # Pre-populate to bypass the interactive prompt in collect_common_inputs so that
  # automated --yes --ts-ip runs don't block on read waiting for a key.
  if is_true "${SKIP_HARDEN}" && [[ -z "${TAILSCALE_AUTH_KEY}" ]]; then
    TAILSCALE_AUTH_KEY="(not-needed)"
  fi
  collect_common_inputs
  if ! is_true "${SKIP_HARDEN}" && [[ -z "${ROOT_PASS}" ]] && [[ -n "${ROOT_PASS_FILE}" ]]; then
    [[ -f "${ROOT_PASS_FILE}" ]] || die "Root password file not found: ${ROOT_PASS_FILE}"
    local file_perms
    file_perms="$(stat -c '%a' "${ROOT_PASS_FILE}" 2>/dev/null || stat -f '%Lp' "${ROOT_PASS_FILE}" 2>/dev/null || echo "unknown")"
    if [[ "${file_perms}" != "unknown" && "${file_perms}" != "600" && "${file_perms}" != "400" ]]; then
      warn "Root password file ${ROOT_PASS_FILE} has permissions ${file_perms}; recommend 0600 or stricter."
    fi
    ROOT_PASS="$(cat "${ROOT_PASS_FILE}")"
    ROOT_PASS="${ROOT_PASS%$'\n'}"
    ROOT_PASS="${ROOT_PASS%$'\r'}"
  fi
  # ROOT_PASS not needed when --ts-ip is supplied (hardening already done)
  if ! is_true "${SKIP_HARDEN}"; then
    [[ -n "${ROOT_PASS}" ]] || prompt_secret ROOT_PASS "Root password"
  fi
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

  [[ "${APP_DOMAIN_MODE}" == "vps" || "${APP_DOMAIN_MODE}" == "apex" ]] \
    || die "App domain mode must be 'vps' or 'apex' (got: ${APP_DOMAIN_MODE})"

  [[ "${DOMAIN}" =~ ${FQDN_RE} ]]         || die "Invalid domain: ${DOMAIN}"
  [[ -n "${CF_API_TOKEN}" ]]               || die "Cloudflare API token is required."
  [[ "${SWAP_SIZE}" =~ ${SWAP_RE} ]]       || die "Invalid swap size: ${SWAP_SIZE} (expected e.g. 2G, 512M)"
  case "${TAILSCALE_DIRECT_WAN,,}" in
    true|false|1|0|yes|no|y|n|on|off) ;;
    *) die "TAILSCALE_DIRECT_WAN must be true/false (got: ${TAILSCALE_DIRECT_WAN})" ;;
  esac

  # Verify companion scripts exist before prompting to proceed
  local scripts=(bootstrap_hardening.sh validate_hardening.sh configure_coolify_binding.sh)
  for script in "${scripts[@]}"; do
    [[ -f "${SCRIPT_DIR}/${script}" ]] || die "Required script not found: ${SCRIPT_DIR}/${script}"
  done
}

# ── SSH wrappers ────────────────────────────────────────────────────────────

ssh_root() {
  [[ -n "${ROOT_PASS_RUNTIME_FILE}" && -f "${ROOT_PASS_RUNTIME_FILE}" ]] \
    || die "Root password runtime file is missing."
  sshpass -f "${ROOT_PASS_RUNTIME_FILE}" ssh "${ROOT_SSH_OPTS[@]}" "root@${SERVER_IP}" "$@"
}

scp_root() {
  [[ -n "${ROOT_PASS_RUNTIME_FILE}" && -f "${ROOT_PASS_RUNTIME_FILE}" ]] \
    || die "Root password runtime file is missing."
  sshpass -f "${ROOT_PASS_RUNTIME_FILE}" scp "${ROOT_SSH_OPTS[@]}" "$@"
}

scp_admin() {
  scp "${SSH_OPTS[@]}" -i "${PRIVATE_KEY}" "$@"
}

ssh_admin() {
  ssh "${SSH_OPTS[@]}" -i "${PRIVATE_KEY}" "${ADMIN_USER}@${TS_IP}" "$@"
}

ssh_admin_sudo() {
  [[ $# -eq 1 ]] || die "ssh_admin_sudo expects exactly one remote command string."
  ssh "${SSH_OPTS[@]}" -i "${PRIVATE_KEY}" "${ADMIN_USER}@${TS_IP}" "sudo $1"
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
  # Hardening owns: log-driver, log-opts, live-restore, default-ipc-mode, storage-driver.
  # Using json-file driver to match Coolify's expectation for compatibility.
  coolify_reconcile_docker_daemon_script | ssh_admin 'sudo bash -s' \
    || die "Failed to reconcile Docker daemon hardening settings."
  pass "Docker daemon hardening reconciled (json-file log rotation + live-restore)"
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
  resolve_app_domain
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
  local deploy_env_tmp
  deploy_env_tmp="$(mktemp)" || die "Failed to create temp file for deploy env"
  {
    printf 'ADMIN_USER=%q\n' "${ADMIN_USER}"
    printf 'ADMIN_PUBKEY=%q\n' "${ADMIN_PUBKEY}"
    printf 'TAILSCALE_CIDR=%q\n' "100.64.0.0/10"
    printf 'SSH_PORT=%q\n' "22"
    printf 'TUNNEL_MODE=%q\n' "${tunnel_flag}"
    printf 'SWAP_SIZE=%q\n' "${SWAP_SIZE}"
    printf 'INSTALL_TAILSCALE=%q\n' "true"
    printf 'TAILSCALE_AUTH_KEY=%q\n' "${TAILSCALE_AUTH_KEY}"
    printf 'TAILSCALE_DIRECT_WAN=%q\n' "${TAILSCALE_DIRECT_WAN}"
    printf 'BIND_DASHBOARD_TO_TAILSCALE=%q\n' "false"
  } > "${deploy_env_tmp}"
  chmod 600 "${deploy_env_tmp}"
  scp_root "${deploy_env_tmp}" "root@${SERVER_IP}:/root/deploy.env"
  rm -f "${deploy_env_tmp}"
  ssh_root "chmod 600 /root/deploy.env"
  pass "Environment file written"

  # Run hardening, streaming output to terminal while capturing it for TS_IP extraction.
  # After hardening, UFW blocks all SSH on the public IP (only tailscale0 allowed), so
  # we cannot open a new root SSH session to run 'tailscale ip -4'. Instead, bootstrap
  # prints 'HARDEN_RESULT_TAILSCALE_IP=<ip>' as the last stdout line; we parse that.
  log "Running bootstrap_hardening.sh (this may take a few minutes)..."
  local harden_tmp
  harden_tmp="$(mktemp)" || die "Failed to create temp file for hardening output"

  # Capture stdout/stderr while preserving failure semantics from the SSH command.
  if ! ssh_root "/root/bootstrap_hardening.sh --env-file /root/deploy.env --install-tailscale --force" \
    2>&1 | tee "${harden_tmp}"; then
    rm -f "${harden_tmp}"
    die "bootstrap_hardening.sh failed. Check server logs: /var/log/bootstrap-hardening.log"
  fi
  pass "Hardening completed"

  # Extract Tailscale IP from captured bootstrap output (sentinel line).
  TS_IP="$(awk -F= '/^HARDEN_RESULT_TAILSCALE_IP=/{ip=$2} END{gsub(/[[:space:]]/,"",ip); print ip}' "${harden_tmp}")"
  rm -f "${harden_tmp}"
  [[ "${TS_IP}" =~ ${IPV4_RE} ]] || die "Failed to get a valid Tailscale IP from bootstrap output."
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

  # Resume safety: if Docker was already installed by a prior partial run, re-apply
  # hardening-owned Docker settings before Gate C validation. This keeps --ts-ip
  # resumes from failing on expected pre-phase3 drift.
  if ssh_admin_sudo 'docker version >/dev/null 2>&1'; then
    log "Gate C pre-check: Docker detected; reconciling daemon and bridge-SSH rules..."
    reconcile_docker_daemon_remote
    ssh_admin_sudo 'systemctl start docker-user-hardening.service 2>/dev/null || true'
    ssh_admin_sudo 'systemctl start docker-ssh-cidr-sync.service 2>/dev/null || true'
  fi

  # Gate C: Validation passes
  log "Gate C: Running validate_hardening.sh..."
  local validate_json
  validate_json="$(ssh_admin_sudo '/root/validate_hardening.sh --json' 2>/dev/null)" || true
  report_validation_result "Gate C" "${validate_json}" \
    "Gate C failed. Fix validation failures before continuing."
}

# ── Phase 3: Docker + Coolify ──────────────────────────────────────────────

phase3_docker_coolify() {
  phase3_has_docker() { ssh_admin_sudo 'docker version >/dev/null 2>&1'; }
  phase3_install_docker() { coolify_install_docker_engine_script | ssh_admin_sudo 'bash -s'; }
  phase3_start_docker_user() { ssh_admin_sudo 'systemctl start docker-user-hardening.service'; }
  phase3_verify_docker_user() { verify_docker_user_gate_remote "$1"; }
  phase3_has_coolify_env() {
    ssh_admin_sudo 'test -f /data/coolify/source/.env && docker inspect coolify >/dev/null 2>&1' >/dev/null 2>&1
  }
  phase3_install_coolify() { coolify_install_coolify_script | ssh_admin_sudo 'bash -s'; }
  phase3_reconcile_docker_daemon() { reconcile_docker_daemon_remote; }
  phase3_restart_docker_user() { ssh_admin_sudo 'systemctl restart docker-user-hardening.service'; }
  phase3_add_coolify_root_key() { coolify_add_coolify_root_key_script | ssh_admin_sudo 'bash -s'; }
  phase3_fix_host_docker_internal() { coolify_fix_host_docker_internal_script | ssh_admin_sudo 'bash -s'; }

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
    phase3_fix_host_docker_internal
}

# ── Phase 4: Binding + DNS ─────────────────────────────────────────────────

phase4_binding_dns() {
  phase4_coolify_env_exists() { ssh_admin_sudo 'test -f /data/coolify/source/.env' >/dev/null 2>&1; }
  phase4_configure_binding() { ssh_admin_sudo "/root/configure_coolify_binding.sh --tailscale-ip ${TS_IP}"; }
  phase4_set_wildcard_domain() {
    local app_domain_q
    app_domain_q="$(printf '%q' "${APP_DOMAIN}")"
    coolify_set_wildcard_domain_script | ssh_admin_sudo "APP_DOMAIN=${app_domain_q} bash -s"
  }
  phase4_reconcile_pusher_env() {
    local deploy_mode_q domain_q
    deploy_mode_q="$(printf '%q' "${DEPLOY_MODE}")"
    domain_q="$(printf '%q' "${DOMAIN}")"
    coolify_reconcile_pusher_env_script \
      | ssh_admin_sudo "DEPLOY_MODE=${deploy_mode_q} DOMAIN=${domain_q} bash -s"
  }
  phase4_install_cloudflared() { coolify_install_cloudflared_script | ssh_admin_sudo 'bash -s'; }
  phase4_configure_cloudflared() {
    local tunnel_id_q tunnel_secret_q cf_account_id_q domain_q app_domain_q cf_zone_name_q
    tunnel_id_q="$(printf '%q' "${TUNNEL_ID}")"
    tunnel_secret_q="$(printf '%q' "${TUNNEL_SECRET}")"
    cf_account_id_q="$(printf '%q' "${CF_ACCOUNT_ID}")"
    domain_q="$(printf '%q' "${DOMAIN}")"
    app_domain_q="$(printf '%q' "${APP_DOMAIN}")"
    cf_zone_name_q="$(printf '%q' "${CF_ZONE_NAME}")"
    coolify_configure_cloudflared_script \
      | ssh_admin_sudo "TUNNEL_ID=${tunnel_id_q} TUNNEL_SECRET=${tunnel_secret_q} CF_ACCOUNT_ID=${cf_account_id_q} DOMAIN=${domain_q} APP_DOMAIN=${app_domain_q} CF_ZONE_NAME=${cf_zone_name_q} bash -s"
  }
  phase4_stop_cloudflared() { ssh_admin_sudo 'systemctl stop cloudflared 2>/dev/null || true'; }

  # Contract anchors kept for tests/docs:
  # mode="${DEPLOY_MODE}"
  # PUSHER_HOST=ws.${DOMAIN}
  # path: /terminal/ws
  # service: http://localhost:6002
  coolify_phase4_binding_dns_shared \
    phase4_coolify_env_exists \
    phase4_configure_binding \
    phase4_set_wildcard_domain \
    phase4_reconcile_pusher_env \
    phase4_install_cloudflared \
    phase4_configure_cloudflared \
    phase4_stop_cloudflared
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
    # On complete failure, output may be empty; default to "000".
    ts_code="$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 10 "http://${TS_IP}:8000" 2>/dev/null)" || ts_code=""
    pub_code="$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 "http://${SERVER_IP}:8000" 2>/dev/null)" || pub_code=""
    # Ensure we have a 3-char code; default to "000" on empty output
    ts_code="${ts_code:-000}"
    pub_code="${pub_code:-000}"
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

  # Gate F: External HTTPS endpoint reachable (validates tunnel/DNS/TLS end-to-end)
  # This is the external vantage point test that the server-side validate_hardening.sh
  # cannot perform — it proves the domain resolves, Cloudflare proxies it, and Coolify responds.
  log "Gate F: Checking external HTTPS endpoint..."
  local https_code attempts=12 attempt delay=10
  local gate_f_passed=false
  for (( attempt=1; attempt<=attempts; attempt++ )); do
    https_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -L "https://${DOMAIN}" 2>/dev/null)" || https_code=""
    # Ensure we have a 3-char code; default to "000" on empty output
    https_code="${https_code:-000}"
    https_code="${https_code:0:3}"
    # Require a successful HTTP response class.
    # 2xx: upstream served content; 3xx: routing/TLS works and redirect happened.
    if [[ "${https_code}" =~ ^[23][0-9][0-9]$ ]]; then
      gate_f_passed=true
      break
    fi
    if (( attempt < attempts )); then
      log "  Gate F not ready (https_code=${https_code}); retrying in ${delay}s (${attempt}/${attempts})..."
      sleep "${delay}"
    fi
  done

  if [[ "${gate_f_passed}" == "true" ]]; then
    pass "Gate F: https://${DOMAIN} reachable (HTTP ${https_code})"
  else
    fail "Gate F: https://${DOMAIN} not reachable with success response (last HTTP ${https_code})"
    die "Gate F failed: external HTTPS endpoint check did not pass."
  fi

  # Final validation run
  log "Running final validate_hardening.sh..."
  local final_validate_json
  final_validate_json="$(ssh_admin_sudo '/root/validate_hardening.sh --json' 2>/dev/null)" || true
  report_validation_result "Final validation" "${final_validate_json}" \
    "Final validation failed. Resolve validation failures before considering deployment complete."

  # Print summary
  print_deployment_summary
}

# ── Main ────────────────────────────────────────────────────────────────────

main() {
  init_ssh_options
  parse_args "$@"
  collect_inputs
  validate_inputs
  init_root_password_auth

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
  is_true "${SKIP_HARDEN}" && log "  TS IP:     ${TS_IP} (--ts-ip; skipping phase 1)"
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

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
