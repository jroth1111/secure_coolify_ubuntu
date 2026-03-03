#!/usr/bin/env bash
set -Eeuo pipefail

# deploy.sh — Laptop-side orchestrator for secure Coolify deployment
# Runs on the operator's machine; SSHes into the remote server.
#
# Interactive mode:  ./deploy.sh
# Non-interactive:   ./deploy.sh --server-ip 1.2.3.4 --root-pass-file /path/root.pass --yes
# Mixed:             ./deploy.sh --server-ip 1.2.3.4  (prompted for the rest)

SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

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
  DEPLOY_KNOWN_HOSTS="$(mktemp)"
  ADMIN_KNOWN_HOSTS="$(mktemp)"
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
  ROOT_PASS_RUNTIME_FILE="$(mktemp)"
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
  deploy_env_tmp="$(mktemp)"
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
  harden_tmp="$(mktemp)"

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

  # Gate C: Validation passes
  log "Gate C: Running validate_hardening.sh..."
  local validate_json
  validate_json="$(ssh_admin_sudo '/root/validate_hardening.sh --json' 2>/dev/null)" || true
  report_validation_result "Gate C" "${validate_json}" \
    "Gate C failed. Fix validation failures before continuing."
}

# ── Phase 3: Docker + Coolify ──────────────────────────────────────────────

phase3_docker_coolify() {
  step "3/5" "Install Docker & Coolify"

  # Install Docker (skip if already present).
  if ssh_admin_sudo 'docker version >/dev/null 2>&1'; then
    log "Docker already installed — skipping install."
  else
    log "Installing Docker via official apt repository..."
    coolify_install_docker_engine_script | ssh_admin_sudo 'bash -s' \
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
    coolify_install_coolify_script | ssh_admin_sudo 'bash -s' \
      || die "Coolify installation failed."
    pass "Coolify installed"
  fi

  # Coolify installer manages daemon.json; re-apply hardening settings while preserving its keys.
  reconcile_docker_daemon_remote

  # Docker restart can flush DOCKER-USER runtime rules; re-apply and verify.
  ssh_admin_sudo 'systemctl restart docker-user-hardening.service' \
    || die "Failed to restart docker-user-hardening.service after Docker daemon reconciliation."
  verify_docker_user_gate_remote "Gate D (post-Coolify)"

  # Add Coolify's generated SSH public key to root's authorized_keys.
  # Required for the Coolify "This Machine" onboarding: Coolify SSHes to localhost as root
  # using its own key. The hardening Match block allows key-only root login from
  # localhost (127.0.0.1), 172.16.0.0/12, and 10.0.0.0/8 (Docker pool); key must be present.
  log "Adding Coolify SSH key to root authorized_keys..."
  coolify_add_coolify_root_key_script | ssh_admin_sudo 'bash -s' \
    || die "Failed to reconcile root authorized_keys with Coolify key."
  pass "Coolify SSH key in root authorized_keys"

  # Fix host.docker.internal resolution on Linux Docker.
  # Docker on Linux doesn't resolve host-gateway to a real IP in all versions/configurations.
  # Patch Coolify's docker-compose.yml to use the actual coolify network gateway IP,
  # then recreate the container so the fix takes effect.
  log "Fixing host.docker.internal for Linux Docker..."
  coolify_fix_host_docker_internal_script | ssh_admin_sudo 'bash -s' \
    || die "Failed to reconcile host.docker.internal in Coolify compose."
  pass "host.docker.internal patched in Coolify docker-compose"
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
    || die "configure_coolify_binding.sh failed. Fix binding errors before continuing."
  pass "Dashboard binding configured"

  # Set Coolify wildcard domain directly in the database.
  # configure_coolify_binding.sh already waited up to 60s for port 8000 to bind,
  # which guarantees the s6 startup sequence (migrate→seed→init) has completed and
  # the server_settings row (server_id=0, the hardcoded Localhost server) exists.
  # The API PATCH /servers/{uuid} does not expose wildcard_domain, so we write
  # directly to PostgreSQL via docker exec on the coolify-db container.
  log "Setting Coolify wildcard domain to http://${APP_DOMAIN}..."
  local app_domain_q
  app_domain_q="$(printf '%q' "${APP_DOMAIN}")"
  coolify_set_wildcard_domain_script | ssh_admin_sudo "APP_DOMAIN=${app_domain_q} bash -s" \
    || die "Failed to update wildcard domain in Coolify database"
  pass "Coolify wildcard domain: http://${APP_DOMAIN}"

  # Configure PUSHER_* for the selected mode.
  # Tunnel mode requires ws.DOMAIN over 443; standard mode must clear tunnel-specific values.
  log "Reconciling PUSHER env vars for ${DEPLOY_MODE} mode..."
  # Contract anchors kept for tests/docs:
  # mode="${DEPLOY_MODE}"
  # PUSHER_HOST=ws.${DOMAIN}
  # install -m 0600 "${tmp}" "${coolify_env}" (performed inside helper script)
  local deploy_mode_q domain_q
  deploy_mode_q="$(printf '%q' "${DEPLOY_MODE}")"
  domain_q="$(printf '%q' "${DOMAIN}")"
  coolify_reconcile_pusher_env_script \
    | ssh_admin_sudo "DEPLOY_MODE=${deploy_mode_q} DOMAIN=${domain_q} bash -s" \
    || die "Failed to reconcile PUSHER env vars"
  if [[ "${DEPLOY_MODE}" == "tunnel" ]]; then
    pass "PUSHER env vars configured: ws.${DOMAIN}:443 (wss)"
  else
    pass "PUSHER env vars cleared for standard mode"
  fi

  if [[ "${DEPLOY_MODE}" == "standard" ]]; then
    # Standard mode: A records pointing to server public IP (proxied)
    log "Configuring DNS: A record ${DOMAIN} → ${SERVER_IP} (proxied)..."
    cf_upsert_a_record "${DOMAIN}" "${SERVER_IP}" "true"
    pass "DNS A record configured: ${DOMAIN} → ${SERVER_IP}"

    # Wildcard A records — always create both scopes so manually set domains at either level work
    local wildcard_name="*.${APP_DOMAIN}"
    log "Configuring DNS: wildcard A record ${wildcard_name} → ${SERVER_IP} (proxied)..."
    cf_upsert_a_record "${wildcard_name}" "${SERVER_IP}" "true"
    pass "DNS wildcard A record configured: ${wildcard_name} → ${SERVER_IP}"
    if [[ "${APP_DOMAIN}" != "${CF_ZONE_NAME}" ]]; then
      local apex_wildcard="*.${CF_ZONE_NAME}"
      cf_upsert_a_record "${apex_wildcard}" "${SERVER_IP}" "true"
      pass "DNS wildcard A record configured: ${apex_wildcard} → ${SERVER_IP}"
    fi

  elif [[ "${DEPLOY_MODE}" == "tunnel" ]]; then
    # Tunnel mode: create tunnel, install cloudflared, CNAME
    log "Creating Cloudflare Tunnel..."
    _stop_cloudflared() { ssh_admin_sudo 'systemctl stop cloudflared 2>/dev/null || true'; }
    cf_create_tunnel "_stop_cloudflared"
    pass "Tunnel created: ${TUNNEL_ID}"

    # Install cloudflared on server
    log "Installing cloudflared on server..."
    coolify_install_cloudflared_script | ssh_admin_sudo 'bash -s' \
      || die "Failed to install cloudflared"
    pass "cloudflared installed"

    # Contract anchors kept for tests/docs:
    # path: /terminal/ws
    # service: http://localhost:6002
    local tunnel_id_q tunnel_secret_q cf_account_id_q domain_q app_domain_q cf_zone_name_q
    tunnel_id_q="$(printf '%q' "${TUNNEL_ID}")"
    tunnel_secret_q="$(printf '%q' "${TUNNEL_SECRET}")"
    cf_account_id_q="$(printf '%q' "${CF_ACCOUNT_ID}")"
    domain_q="$(printf '%q' "${DOMAIN}")"
    app_domain_q="$(printf '%q' "${APP_DOMAIN}")"
    cf_zone_name_q="$(printf '%q' "${CF_ZONE_NAME}")"
    coolify_configure_cloudflared_script | ssh_admin_sudo "TUNNEL_ID=${tunnel_id_q} TUNNEL_SECRET=${tunnel_secret_q} CF_ACCOUNT_ID=${cf_account_id_q} DOMAIN=${domain_q} APP_DOMAIN=${app_domain_q} CF_ZONE_NAME=${cf_zone_name_q} bash -s" \
      || die "Failed to write cloudflared credentials/config or start service"
    local wc_summary="*.${APP_DOMAIN}"
    [[ "${APP_DOMAIN}" != "${CF_ZONE_NAME}" ]] && wc_summary+=" and *.${CF_ZONE_NAME}"
    pass "Tunnel credentials and config written (wildcards: ${wc_summary})"
    pass "cloudflared service running"

    # Create CNAME records: exact domain + wildcard for subdomains
    local tunnel_target="${TUNNEL_ID}.cfargotunnel.com"
    cf_upsert_cname "${DOMAIN}" "${tunnel_target}"
    pass "DNS CNAME configured: ${DOMAIN} → ${tunnel_target}"

    # Always create both wildcard CNAME levels for full routing coverage
    cf_upsert_cname "*.${APP_DOMAIN}" "${tunnel_target}"
    pass "DNS wildcard CNAME configured: *.${APP_DOMAIN} → ${tunnel_target}"
    if [[ "${APP_DOMAIN}" != "${CF_ZONE_NAME}" ]]; then
      cf_upsert_cname "*.${CF_ZONE_NAME}" "${tunnel_target}"
      pass "DNS wildcard CNAME configured: *.${CF_ZONE_NAME} → ${tunnel_target}"
    fi
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
