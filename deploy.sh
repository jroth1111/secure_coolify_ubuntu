#!/usr/bin/env bash
if [[ -z "${BASH_VERSINFO:-}" || "${BASH_VERSINFO[0]}" -lt 4 ]]; then
  for candidate in /opt/homebrew/bin/bash /usr/local/bin/bash; do
    if [[ -x "${candidate}" ]]; then
      exec "${candidate}" "$0" "$@"
    fi
  done
  printf 'FATAL: %s requires Bash 4+ (found %s). On macOS: brew install bash, then run with /opt/homebrew/bin/bash %s ...\n' \
    "$(basename "$0")" "${BASH_VERSION:-unknown}" "$(basename "$0")" >&2
  exit 1
fi
set -Eeuo pipefail

# deploy.sh — Laptop-side orchestrator for secure Coolify deployment
# Runs on the operator's machine; SSHes into the remote server.
#
# Interactive mode:  ./deploy.sh
# Non-interactive:   ./deploy.sh --server-ip 1.2.3.4 --root-pass-file /path/root.pass --yes
# Mixed:             ./deploy.sh --server-ip 1.2.3.4  (prompted for the rest)

SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=overlays/coolify/coolify-common.sh
source "${SCRIPT_DIR}/overlays/coolify/coolify-common.sh"
# shellcheck source=lib/overlay-loader.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/overlay-loader.sh"

# ── Inputs (populated by flags or prompts) ──────────────────────────────────

SERVER_IP="${SERVER_IP:-}"
ROOT_PASS="${ROOT_PASS:-}"
ROOT_PASS_FILE="${ROOT_PASS_FILE:-}"
ROOT_PASS_RUNTIME_FILE=""
PAAS="${PAAS:-coolify}"
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
PRIVATE_TLS_CA="${PRIVATE_TLS_CA:-}"
ZEROSSL_EAB_KID="${ZEROSSL_EAB_KID:-}"
ZEROSSL_EAB_KID_FILE="${ZEROSSL_EAB_KID_FILE:-}"
ZEROSSL_EAB_HMAC="${ZEROSSL_EAB_HMAC:-}"
ZEROSSL_EAB_HMAC_FILE="${ZEROSSL_EAB_HMAC_FILE:-}"
AUTO_YES="${AUTO_YES:-false}"
SKIP_HARDEN="${SKIP_HARDEN:-false}"  # set via --ts-ip to resume after partial harden
PREFLIGHT_ONLY="${PREFLIGHT_ONLY:-false}"

# ── Derived at runtime ──────────────────────────────────────────────────────

ADMIN_PUBKEY=""
PRIVATE_KEY=""
TS_IP=""
CF_ZONE_NAME=""
APP_DOMAIN=""
TUNNEL_ID=""
TUNNEL_SECRET=""
REMOTE_DEPLOY_ENV_PATH="/root/deploy.env"
DEPLOY_ENV_REMOTE_PENDING="false"
ROOT_SSH_HOST=""

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

sync_operator_known_host_entries() {
  local source_file="${1:-}"
  shift || true
  [[ -n "${HOME:-}" ]] || return 0
  [[ -n "${source_file}" && -s "${source_file}" ]] || return 0

  local ssh_dir="${HOME}/.ssh"
  local operator_known_hosts="${ssh_dir}/known_hosts"
  if ! mkdir -p "${ssh_dir}" 2>/dev/null; then
    warn "Could not create ${ssh_dir}; skipping operator known_hosts refresh."
    return 0
  fi
  chmod 700 "${ssh_dir}" >/dev/null 2>&1 || true
  if ! touch "${operator_known_hosts}" 2>/dev/null; then
    warn "Could not write ${operator_known_hosts}; skipping operator known_hosts refresh."
    return 0
  fi
  chmod 600 "${operator_known_hosts}" >/dev/null 2>&1 || true

  local host
  for host in "$@"; do
    [[ -n "${host}" ]] || continue
    ssh-keygen -R "${host}" -f "${operator_known_hosts}" >/dev/null 2>&1 || true
  done

  local line added=0
  while IFS= read -r line; do
    [[ -n "${line}" ]] || continue
    if ! grep -qxF -- "${line}" "${operator_known_hosts}" 2>/dev/null; then
      printf '%s\n' "${line}" >> "${operator_known_hosts}" || {
        warn "Could not update ${operator_known_hosts}; skipping remaining operator known_hosts refresh."
        return 0
      }
      added=$((added + 1))
    fi
  done < "${source_file}"

  if (( added > 0 )) && [[ $# -gt 0 ]]; then
    log "Operator known_hosts refreshed for: $*"
  fi
}

cleanup_remote_deploy_env() {
  [[ "${DEPLOY_ENV_REMOTE_PENDING}" == "true" ]] || return 0

  local cleaned="false"
  if [[ -n "${TS_IP:-}" && -n "${ADMIN_USER:-}" && -n "${PRIVATE_KEY:-}" && ${#SSH_OPTS[@]} -gt 0 ]]; then
    if ssh_admin_sudo "rm -f ${REMOTE_DEPLOY_ENV_PATH}" >/dev/null 2>&1; then
      cleaned="true"
    fi
  fi

  if [[ "${cleaned}" != "true" && -n "${ROOT_SSH_HOST:-}" && -n "${ROOT_PASS_RUNTIME_FILE:-}" && -f "${ROOT_PASS_RUNTIME_FILE}" && ${#ROOT_SSH_OPTS[@]} -gt 0 ]]; then
    if ssh_root "rm -f ${REMOTE_DEPLOY_ENV_PATH}" >/dev/null 2>&1; then
      cleaned="true"
    fi
  fi

  if [[ "${cleaned}" == "true" ]]; then
    DEPLOY_ENV_REMOTE_PENDING="false"
  fi
}

deploy_exit_trap() {
  local exit_code=$?
  cleanup_remote_deploy_env
  cleanup_temp_files
  run_report_finalize "${exit_code}"
}

init_ssh_options() {
  # Use accept-new: accept on first connect, reject changed keys (OpenSSH 7.6+).
  DEPLOY_KNOWN_HOSTS="$(mktemp)" || die "Failed to create temp file for deploy known hosts"
  ADMIN_KNOWN_HOSTS="$(mktemp)" || die "Failed to create temp file for admin known hosts"

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
    -o PubkeyAuthentication=no
    -o NumberOfPasswordPrompts=1
    -o PreferredAuthentications=keyboard-interactive,password
  )
  ROOT_SSH_HOST="${SERVER_IP}"
}

init_root_password_auth() {
  if is_true "${SKIP_HARDEN}" || is_true "${PREFLIGHT_ONLY}"; then
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
  Root password                 Required unless --preflight-only or --ts-ip is used
  --tailscale-auth-key <key>    Required unless --preflight-only or --ts-ip is used
  --domain <fqdn>               Domain name for Coolify
  Cloudflare API token          Provide via CF_API_TOKEN, --cf-api-token-file, or prompt

Optional:
  --cf-api-token-file <path>    File containing Cloudflare API token
  --cf-tunnel-api-token-file <path>
                                File containing Cloudflare tunnel API token (optional; defaults to API token)
  --admin-user <name>           Admin username (default: coolifyadmin)
  --root-pass-file <path>       Read root password from file (recommended for automation)
  --pubkey-file <path>          SSH public key file (default: ~/.ssh/id_ed25519.pub)
  --mode <tunnel|standard>       Deployment mode (default: tunnel)
  --app-domain-mode <vps|apex>  App subdomain scope: vps=appname.DOMAIN, apex=appname.ZONE (default: apex)
  --cf-zone <zone>              Cloudflare zone (default: derived from domain)
  --cf-zone-id <id>             Cloudflare zone ID override (32-char hex)
  --cf-account-id <id>          Cloudflare account ID override (32-char hex)
  --swap-size <size>            Swap size (default: 2G)
  --server-timezone <IANA>      Server timezone (for example: Australia/Melbourne, UTC)
  --private-tls-ca <letsencrypt|zerossl>
                                Private dashboard/websocket CA in tunnel mode (default: letsencrypt)
  --zerossl-eab-kid-file <path> File containing ZeroSSL EAB kid (required when --private-tls-ca zerossl)
  --zerossl-eab-hmac-file <path>
                                File containing ZeroSSL EAB hmac (required when --private-tls-ca zerossl)
  --tailscale-direct-wan        Allow WAN UDP 41641 for direct Tailscale paths (optional optimization)
  --no-tailscale-direct-wan     Keep WAN UDP 41641 closed (default; DERP fallback remains available)
  --preflight-only              Run local/Cloudflare preflight checks only, then exit
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
      --private-tls-ca)  PRIVATE_TLS_CA="${2:?--private-tls-ca requires a value}"; shift 2 ;;
      --zerossl-eab-kid-file) ZEROSSL_EAB_KID_FILE="${2:?--zerossl-eab-kid-file requires a value}"; shift 2 ;;
      --zerossl-eab-hmac-file) ZEROSSL_EAB_HMAC_FILE="${2:?--zerossl-eab-hmac-file requires a value}"; shift 2 ;;
      --tailscale-direct-wan) TAILSCALE_DIRECT_WAN="true"; shift ;;
      --no-tailscale-direct-wan) TAILSCALE_DIRECT_WAN="false"; shift ;;
      --preflight-only)  PREFLIGHT_ONLY="true"; shift ;;
      --paas)            PAAS="${2:-coolify}"; shift 2 ;;
      --yes)             AUTO_YES="true"; shift ;;
      --ts-ip)           TS_IP="${2:?--ts-ip requires a value}"; SKIP_HARDEN="true"; shift 2 ;;
      -h|--help)         usage; exit 0 ;;
      *)                 die "Unknown option: $1 (use --help)" ;;
    esac
  done
}

# ── Input collection (flag → prompt fallback) ──────────────────────────────

collect_inputs() {
  # When hardening is being skipped (--ts-ip) or only preflight is requested,
  # tailscale auth key is not needed.
  # Pre-populate to bypass the interactive prompt in collect_common_inputs so that
  # automated --yes --ts-ip runs don't block on read waiting for a key.
  if { is_true "${SKIP_HARDEN}" || is_true "${PREFLIGHT_ONLY}"; } \
    && [[ -z "${TAILSCALE_AUTH_KEY}" ]]; then
    TAILSCALE_AUTH_KEY="(not-needed)"
  fi
  collect_common_inputs
  if ! is_true "${SKIP_HARDEN}" && ! is_true "${PREFLIGHT_ONLY}" \
    && [[ -z "${ROOT_PASS}" ]] && [[ -n "${ROOT_PASS_FILE}" ]]; then
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
  if ! is_true "${SKIP_HARDEN}" && ! is_true "${PREFLIGHT_ONLY}"; then
    [[ -n "${ROOT_PASS}" ]] || prompt_secret ROOT_PASS "Root password"
  fi
}

# ── Input validation ───────────────────────────────────────────────────────

validate_inputs() {
  [[ "${SERVER_IP}" =~ ${IPV4_RE} ]]      || die "Invalid server IP: ${SERVER_IP}"
  finalize_cloudflare_tokens
  finalize_private_tls_ca_inputs

  # ROOT_PASS not required when --ts-ip or --preflight-only is supplied.
  if ! is_true "${SKIP_HARDEN}" && ! is_true "${PREFLIGHT_ONLY}"; then
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

  # Auth key only required when hardening will run; --ts-ip / --preflight-only skip hardening.
  if ! is_true "${SKIP_HARDEN}" && ! is_true "${PREFLIGHT_ONLY}"; then
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
  [[ "${PRIVATE_TLS_CA}" == "letsencrypt" || "${PRIVATE_TLS_CA}" == "zerossl" ]] \
    || die "Private TLS CA must be 'letsencrypt' or 'zerossl' (got: ${PRIVATE_TLS_CA})"
  if [[ "${DEPLOY_MODE}" == "tunnel" && "${PRIVATE_TLS_CA}" == "zerossl" ]]; then
    [[ -n "${ZEROSSL_EAB_KID}" ]] || die "ZeroSSL EAB kid is required when --private-tls-ca zerossl."
    [[ -n "${ZEROSSL_EAB_HMAC}" ]] || die "ZeroSSL EAB hmac is required when --private-tls-ca zerossl."
  fi

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

  # Verify companion scripts exist before prompting to proceed
  local scripts=(base/bootstrap.sh base/validate.sh overlays/coolify/configure_coolify_binding.sh)
  for script in "${scripts[@]}"; do
    [[ -f "${SCRIPT_DIR}/${script}" ]] || die "Required script not found: ${SCRIPT_DIR}/${script}"
  done
}

# ── SSH wrappers ────────────────────────────────────────────────────────────

ssh_root() {
  [[ -n "${ROOT_PASS_RUNTIME_FILE}" && -f "${ROOT_PASS_RUNTIME_FILE}" ]] \
    || die "Root password runtime file is missing."
  [[ -n "${ROOT_SSH_HOST:-}" ]] || die "ROOT_SSH_HOST is not set."
  sshpass -f "${ROOT_PASS_RUNTIME_FILE}" ssh "${ROOT_SSH_OPTS[@]}" "root@${ROOT_SSH_HOST}" "$@"
}

scp_root() {
  [[ -n "${ROOT_PASS_RUNTIME_FILE}" && -f "${ROOT_PASS_RUNTIME_FILE}" ]] \
    || die "Root password runtime file is missing."
  sshpass -f "${ROOT_PASS_RUNTIME_FILE}" scp "${ROOT_SSH_OPTS[@]}" "$@"
}

retry_root_transport() {
  local description="$1"
  shift

  local attempt rc
  for attempt in 1 2 3; do
    if "$@"; then
      return 0
    else
      rc=$?
    fi
    if (( rc == 255 && attempt < 3 )); then
      warn "${description} failed with SSH/SCP exit 255 on attempt ${attempt}/3; retrying in 3s."
      sleep 3
      continue
    fi
    return "${rc}"
  done
}

extract_bootstrap_tailscale_ip() {
  local capture_file="${1:-}"
  [[ -n "${capture_file}" && -f "${capture_file}" ]] || return 0
  awk -F= '/^HARDEN_RESULT_TAILSCALE_IP=/{ip=$2} END{gsub(/[[:space:]]/,"",ip); print ip}' "${capture_file}"
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
  local scripts=(base/bootstrap.sh base/validate.sh overlays/coolify/configure_coolify_binding.sh)
  log "Syncing companion scripts to server /root/..."
  for script in "${scripts[@]}"; do
    local local_path="${SCRIPT_DIR}/${script}"
    [[ -f "${local_path}" ]] || die "Script not found: ${local_path}"
    local script_bn script_dn remote_dir
    script_bn="$(basename "${script}")"
    script_dn="$(dirname "${script}")"
    [[ "${script_dn}" == "." ]] && remote_dir="/root" || remote_dir="/root/${script_dn}"
    ssh_admin_sudo "install -d -m 0755 -o root -g root '${remote_dir}'" \
      || die "Failed to create ${remote_dir} on server"
    scp_admin "${local_path}" "${ADMIN_USER}@${TS_IP}:/tmp/${script_bn}" \
      || die "Failed to upload ${script}"
    ssh_admin_sudo "bash -c 'mv /tmp/${script_bn} ${remote_dir}/${script_bn} && chmod 755 ${remote_dir}/${script_bn}'" \
      || die "Failed to install ${script} to ${remote_dir}/"
  done

  local lib_files=(lib/common.sh lib/tailscale.sh)
  ssh_admin_sudo 'install -d -m 0755 -o root -g root /root/lib' \
    || die "Failed to create /root/lib on server"
  for libfile in "${lib_files[@]}"; do
    local libpath="${SCRIPT_DIR}/${libfile}"
    local libname
    libname="$(basename "${libfile}")"
    [[ -f "${libpath}" ]] || die "Library not found: ${libpath}"
    scp_admin "${libpath}" "${ADMIN_USER}@${TS_IP}:/tmp/${libname}" \
      || die "Failed to upload ${libfile}"
    ssh_admin_sudo "bash -c 'mv /tmp/${libname} /root/lib/${libname} && chmod 644 /root/lib/${libname}'" \
      || die "Failed to install ${libfile} to /root/lib/"
  done

  # Upload overlay files (coolify)
  local overlay_files=(
    overlays/coolify/coolify-common.sh
    overlays/coolify/modules/binding.sh
    overlays/coolify/modules/binding_watchdog.sh
    overlays/coolify/checks/coolify_binding_check.sh
    overlays/coolify/checks/unattended_upgrades_check.sh
    overlays/coolify/checks/coolify_ssh_check.sh
    overlays/coolify/checks/cloudflared_check.sh
    overlays/coolify/checks/coolify_container_check.sh
    overlays/coolify/checks/coolify_instance_settings_check.sh
    overlays/coolify/checks/validate_timer_check.sh
  )
  for ofile in "${overlay_files[@]}"; do
    local opath="${SCRIPT_DIR}/${ofile}"
    local odir
    odir="$(dirname "${ofile}")"
    [[ -f "${opath}" ]] || die "Overlay file not found: ${opath}"
    ssh_admin_sudo "install -d -m 0755 -o root -g root '/root/${odir}'" \
      || die "Failed to create /root/${odir} on server"
    local obase
    obase="$(basename "${ofile}")"
    scp_admin "${opath}" "${ADMIN_USER}@${TS_IP}:/tmp/${obase}" \
      || die "Failed to upload ${ofile}"
    ssh_admin_sudo "bash -c 'mv /tmp/${obase} /root/${odir}/${obase} && chmod 644 /root/${odir}/${obase}'" \
      || die "Failed to install ${ofile} to /root/${odir}/"
  done

  # Upload docker-host overlay files
  local dh_files=(
    overlays/docker-host/modules/cidrs.sh
    overlays/docker-host/modules/detect.sh
    overlays/docker-host/modules/readiness.sh
    overlays/docker-host/modules/user_rules.sh
    overlays/docker-host/modules/daemon.sh
    overlays/docker-host/modules/cidr_sync_timer.sh
    overlays/docker-host/modules/ssh_match_dropin.sh
    overlays/docker-host/checks/_helpers.sh
    overlays/docker-host/checks/docker_user_check.sh
    overlays/docker-host/checks/docker_user_lifecycle_check.sh
    overlays/docker-host/checks/docker_ssh_cidr_sync_check.sh
    overlays/docker-host/checks/docker_daemon_check.sh
    overlays/docker-host/checks/docker_trust_boundary_check.sh
  )
  for dfile in "${dh_files[@]}"; do
    local dpath="${SCRIPT_DIR}/${dfile}"
    local ddir
    ddir="$(dirname "${dfile}")"
    [[ -f "${dpath}" ]] || die "Overlay file not found: ${dpath}"
    ssh_admin_sudo "install -d -m 0755 -o root -g root '/root/${ddir}'" \
      || die "Failed to create /root/${ddir} on server"
    local dbase
    dbase="$(basename "${dfile}")"
    scp_admin "${dpath}" "${ADMIN_USER}@${TS_IP}:/tmp/${dbase}" \
      || die "Failed to upload ${dfile}"
    ssh_admin_sudo "bash -c 'mv /tmp/${dbase} /root/${ddir}/${dbase} && chmod 644 /root/${ddir}/${dbase}'" \
      || die "Failed to install ${dfile} to /root/${ddir}/"
  done

  # Upload base module and check files
  local base_files=(
    base/modules/os_detect.sh base/modules/system.sh base/modules/bootloader.sh
    base/modules/services.sh base/modules/kernel_sysctl.sh base/modules/fail2ban.sh
    base/modules/ssh.sh base/modules/ssh_socket.sh base/modules/password_policy.sh
    base/modules/ufw.sh base/modules/rsyslog.sh base/modules/journald.sh
    base/modules/auditd.sh base/modules/unattended.sh base/modules/post_checks.sh
    base/modules/state.sh base/modules/validation_timer.sh
    base/checks/_runtime.sh base/checks/ssh_check.sh base/checks/ufw_check.sh
    base/checks/sysctl_check.sh base/checks/fail2ban_check.sh base/checks/auditd_check.sh
    base/checks/journald_check.sh base/checks/rsyslog_check.sh base/checks/timesync_check.sh
    base/checks/timezone_check.sh base/checks/swap_check.sh base/checks/bootloader_check.sh
    base/checks/reboot_required_check.sh base/checks/banner_check.sh base/checks/admin_sudo_check.sh
    base/checks/apparmor_check.sh base/checks/disabled_services_check.sh base/checks/apport_check.sh
    base/checks/cron_check.sh base/checks/networkd_wait_online_check.sh base/checks/tailscale_check.sh
  )
  for bfile in "${base_files[@]}"; do
    local bpath="${SCRIPT_DIR}/${bfile}"
    local bdir
    bdir="$(dirname "${bfile}")"
    [[ -f "${bpath}" ]] || die "Base file not found: ${bpath}"
    ssh_admin_sudo "install -d -m 0755 -o root -g root '/root/${bdir}'" \
      || die "Failed to create /root/${bdir} on server"
    local bbase
    bbase="$(basename "${bfile}")"
    scp_admin "${bpath}" "${ADMIN_USER}@${TS_IP}:/tmp/${bbase}" \
      || die "Failed to upload ${bfile}"
    ssh_admin_sudo "bash -c 'mv /tmp/${bbase} /root/${bdir}/${bbase} && chmod 644 /root/${bdir}/${bbase}'" \
      || die "Failed to install ${bfile} to /root/${bdir}/"
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
  local required_cmds=(ssh scp curl jq sshpass ssh-keygen openssl tar)
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
  cf_verify_dns_write_token
  cf_get_account_id  # always fetch — needed for tunnel (default mode)
  cf_verify_tunnel_token
  resolve_app_domain
  cf_verify_private_tls_ca_caa
  pass "Cloudflare API verified (zone: ${CF_ZONE_ID})"

  # Test SSH connectivity (skipped for --ts-ip and --preflight-only).
  if is_true "${SKIP_HARDEN}" || is_true "${PREFLIGHT_ONLY}"; then
    log "Skipping root SSH check (--ts-ip/--preflight-only mode)."
  else
    log "Testing SSH to root@${SERVER_IP}..."
    if ssh_root 'echo ok' >/dev/null 2>&1; then
      sync_operator_known_host_entries "${DEPLOY_KNOWN_HOSTS}" "${SERVER_IP}"
      pass "SSH root@${SERVER_IP} reachable"
    else
      die "Cannot SSH to root@${SERVER_IP}. Check IP and root password."
    fi
  fi
}

# ── Phase 1: Upload + Harden ───────────────────────────────────────────────

phase1_upload_harden() {
  step "1/5" "Upload scripts & harden server"
  local bootstrap_cmd bootstrap_cmd_script
  bootstrap_cmd_script="$(cat <<EOF
set -Eeuo pipefail
cleanup() { rm -f -- ${REMOTE_DEPLOY_ENV_PATH@Q}; }
trap cleanup EXIT
/root/base/bootstrap.sh --env-file ${REMOTE_DEPLOY_ENV_PATH@Q} --install-tailscale --force
EOF
)"
  printf -v bootstrap_cmd 'bash -lc %q' "${bootstrap_cmd_script}"
  local bootstrap_transport="root"

  # Upload deployment tree as a single tarball. base/, lib/, and overlays/
  # together contain every file bootstrap.sh and validate.sh source, so packaging
  # them in one transfer keeps phase 1 robust against per-file SSH bursts on
  # password-authenticated transports. Phase 2 sync_companion_scripts later
  # re-syncs the same tree via admin SSH for resume runs.
  for d in base lib overlays; do
    [[ -d "${SCRIPT_DIR}/${d}" ]] || die "Required directory not found: ${SCRIPT_DIR}/${d}"
  done
  local tree_tar
  tree_tar="$(mktemp -t deploy-tree.XXXXXXXX.tar.gz)" || die "Failed to create temp tarball"
  if ! ( cd "${SCRIPT_DIR}" && tar -czf "${tree_tar}" base lib overlays ); then
    rm -f "${tree_tar}"
    die "Failed to package deployment tree from ${SCRIPT_DIR}"
  fi

  if ! retry_root_transport "Uploading deployment tree to ${SERVER_IP}" \
       scp_root "${tree_tar}" "root@${SERVER_IP}:/root/deploy-tree.tar.gz"; then
    rm -f "${tree_tar}"
    die "Failed to upload deployment tree to ${SERVER_IP}"
  fi
  rm -f "${tree_tar}"

  retry_root_transport "Extracting deployment tree on ${SERVER_IP}" \
    ssh_root "tar -C /root -xzf /root/deploy-tree.tar.gz && rm -f /root/deploy-tree.tar.gz && chmod 755 /root/base/bootstrap.sh /root/base/validate.sh /root/overlays/coolify/configure_coolify_binding.sh" \
    || die "Failed to extract deployment tree on ${SERVER_IP}"
  pass "Scripts uploaded"

  # We have just opened a burst of short-lived root password-auth sessions for upload/chmod.
  # Some providers intermittently wobble on the first immediately-following long SSH command,
  # even though root password auth is otherwise valid. Re-probe the transport here before
  # placing secrets on the server so a failing transport does not strand deploy.env remotely.
  if ! retry_root_transport "Pre-bootstrap root SSH probe to ${SERVER_IP}" ssh_root 'true'; then
    die "Root SSH probe failed after companion upload burst; refusing to upload deploy.env or start base/bootstrap.sh."
  fi
  pass "Root SSH probe succeeded before deploy env upload"

  # Write env file on server (avoids quoting issues with SSH pubkey)
  local tunnel_flag="false"
  [[ "${DEPLOY_MODE}" == "tunnel" ]] && tunnel_flag="true"
  local deploy_env_tmp
  deploy_env_tmp="$(mktemp)" || die "Failed to create temp file for deploy env"
  {
    printf 'ADMIN_USER="%s"\n' "${ADMIN_USER//\"/\\\"}"
    printf 'ADMIN_PUBKEY="%s"\n' "${ADMIN_PUBKEY//\"/\\\"}"
    printf 'DOMAIN="%s"\n' "${DOMAIN//\"/\\\"}"
    printf 'TAILSCALE_CIDR="100.64.0.0/10"\n'
    printf 'SSH_PORT="22"\n'
    printf 'TUNNEL_MODE="%s"\n' "${tunnel_flag//\"/\\\"}"
    printf 'SWAP_SIZE="%s"\n' "${SWAP_SIZE//\"/\\\"}"
    printf 'TIMEZONE="%s"\n' "${SERVER_TIMEZONE//\"/\\\"}"
    printf 'INSTALL_TAILSCALE="true"\n'
    printf 'TAILSCALE_AUTH_KEY="%s"\n' "${TAILSCALE_AUTH_KEY//\"/\\\"}"
    printf 'TAILSCALE_DIRECT_WAN="%s"\n' "${TAILSCALE_DIRECT_WAN//\"/\\\"}"
    printf 'BIND_DASHBOARD_TO_TAILSCALE="false"\n'
  } > "${deploy_env_tmp}"
  chmod 600 "${deploy_env_tmp}"
  if ! scp_root "${deploy_env_tmp}" "root@${SERVER_IP}:${REMOTE_DEPLOY_ENV_PATH}"; then
    rm -f "${deploy_env_tmp}"
    die "Failed to upload deploy env file to ${SERVER_IP}"
  fi
  rm -f "${deploy_env_tmp}"
  if ! ssh_root "chmod 600 ${REMOTE_DEPLOY_ENV_PATH}"; then
    die "Failed to set permissions on ${REMOTE_DEPLOY_ENV_PATH}"
  fi
  DEPLOY_ENV_REMOTE_PENDING="true"
  pass "Environment file written"

  # Run hardening, streaming output to terminal while capturing it for TS_IP extraction.
  # bootstrap_hardening.sh emits HARDEN_RESULT_TAILSCALE_IP as soon as Tailscale is
  # verified, and again at the end. Retries pivot to root@TS_IP first, then to
  # admin@TS_IP via sudo once root password auth is no longer a valid recovery path.
  log "Running bootstrap_hardening.sh (this may take a few minutes)..."
  local harden_tmp bootstrap_attempt bootstrap_rc
  harden_tmp="$(mktemp)" || die "Failed to create temp file for hardening output"
  bootstrap_rc=0

  bootstrap_remote_exec() {
    if [[ "${bootstrap_transport}" == "admin" ]]; then
      ssh_admin_sudo "${bootstrap_cmd}"
    else
      ssh_root "${bootstrap_cmd}"
    fi
  }

  bootstrap_remote_tail_log() {
    if [[ "${bootstrap_transport}" == "admin" ]]; then
      ssh_admin_sudo 'tail -n 50 /var/log/server-hardening.log 2>/dev/null || true'
    else
      ssh_root 'tail -n 50 /var/log/server-hardening.log 2>/dev/null || true'
    fi
  }

  promote_bootstrap_transport_to_admin() {
    [[ "${bootstrap_transport}" == "admin" ]] && return 0
    [[ "${TS_IP:-}" =~ ${IPV4_RE} ]] || return 1
    if ssh_admin 'echo ok' >/dev/null 2>&1; then
      bootstrap_transport="admin"
      log "Phase 1 fallback: switching bootstrap retries to ${ADMIN_USER}@${TS_IP} via sudo"
      return 0
    fi
    return 1
  }

  # Capture stdout/stderr while preserving failure semantics from the SSH command.
  # Emit heartbeat lines so the operator sees progress even when apt/tee is quiet.
  for bootstrap_attempt in 1 2 3; do
    if run_with_heartbeat \
      "bootstrap_hardening.sh via ${bootstrap_transport}@${ROOT_SSH_HOST:-${TS_IP:-${SERVER_IP}}} (attempt ${bootstrap_attempt}/3)" \
      stream_command_output "${harden_tmp}" \
      bootstrap_remote_exec; then
      bootstrap_rc=0
      break
    else
      bootstrap_rc=$?
      local captured_ts_ip=""
      captured_ts_ip="$(extract_bootstrap_tailscale_ip "${harden_tmp}")"
      if [[ "${captured_ts_ip}" =~ ${IPV4_RE} ]]; then
        TS_IP="${captured_ts_ip}"
        if [[ "${ROOT_SSH_HOST}" != "${TS_IP}" ]]; then
          ROOT_SSH_HOST="${TS_IP}"
          log "Phase 1 fallback: switching root retries to Tailscale IP ${TS_IP}"
        fi
      fi
      if (( bootstrap_rc == 255 && bootstrap_attempt < 3 )); then
        if promote_bootstrap_transport_to_admin; then
          warn "bootstrap_hardening.sh SSH transport failed on attempt ${bootstrap_attempt}/3; retrying via admin sudo in 3s."
        else
          warn "bootstrap_hardening.sh SSH transport/auth failed on attempt ${bootstrap_attempt}/3; retrying in 3s."
        fi
        sleep 3
        continue
      fi
      break
    fi
  done

  if (( bootstrap_rc != 0 )); then
    warn "bootstrap_hardening.sh failed. Last 50 lines of captured output:"
    tail -n 50 "${harden_tmp}" || true
    warn "Attempting to fetch remote /var/log/server-hardening.log tail (best effort)..."
    bootstrap_remote_tail_log || true
    rm -f "${harden_tmp}"
    die "bootstrap_hardening.sh failed. Check server logs: /var/log/server-hardening.log"
  fi
  pass "Hardening completed"

  # Extract Tailscale IP from captured bootstrap output (sentinel line).
  TS_IP="$(extract_bootstrap_tailscale_ip "${harden_tmp}")"
  rm -f "${harden_tmp}"
  [[ "${TS_IP}" =~ ${IPV4_RE} ]] || die "Failed to get a valid Tailscale IP from bootstrap output."
  pass "Server Tailscale IP: ${TS_IP}"

  # deploy.env cleanup is attempted by the remote bootstrap wrapper and retained
  # as a phase2/EXIT-trap fallback in case the remote session dies mid-transition.
}

phase1_skipped() {
  step "1/5" "Upload scripts & harden server (skipped)"
  pass "Phase 1 skipped: --ts-ip supplied (${TS_IP})"
}

# ── Phase 2: Gate checks ───────────────────────────────────────────────────

wait_for_admin_ssh_or_die() {
  local context="$1"
  local max_attempts="${2:-6}"
  local delay="${3:-10}"
  local attempt

  for (( attempt=1; attempt<=max_attempts; attempt++ )); do
    if ssh_admin 'echo ok' >/dev/null 2>&1; then
      return 0
    fi
    if (( attempt == max_attempts )); then
      break
    fi
    log "  ${context}: attempt ${attempt}/${max_attempts} failed, retrying in ${delay}s..."
    sleep "${delay}"
  done
  return 1
}

gate_c_failures_are_transient() {
  local json="$1"
  [[ -n "${json}" ]] || return 1
  jq -e '
    .checks
    | [ .[] | select(.status=="FAIL") | .check ] as $fails
    | ($fails|length) > 0
      and
      all($fails[];
        . == "timesync: NTPSynchronized"
        or . == "fail2ban: active"
        or . == "fail2ban: sshd jail"
        or . == "fail2ban: f2b-sshd iptables chain"
        or . == "docker-user: IPv4"
      )
  ' >/dev/null 2>&1 <<< "${json}"
}

assert_resume_phase1_contract_remote() {
  is_true "${SKIP_HARDEN}" || return 0

  local state_line state_domain state_tunnel_mode expected_tunnel_mode
  expected_tunnel_mode="false"
  [[ "${DEPLOY_MODE}" == "tunnel" ]] && expected_tunnel_mode="true"

  state_line="$(ssh_admin_sudo 'bash -ceu '"'"'
    state_file="/var/lib/server-hardening/state"
    state_lock_file="${state_file}.lock"
    state_snapshot="$(mktemp)"
    cleanup() {
      rm -f "${state_snapshot}"
    }
    trap cleanup EXIT
    [[ -f "${state_file}" ]] || exit 4
    if command -v flock >/dev/null 2>&1; then
      flock -s "${state_lock_file}" bash -ceu '\''cat "$1" > "$2"'\'' _ "${state_file}" "${state_snapshot}"
    else
      cat "${state_file}" > "${state_snapshot}"
    fi
    # shellcheck disable=SC1090
    source "${state_snapshot}"
    printf "%s\t%s\n" "${domain:-}" "${tunnel_mode:-}"
  '"'" 2>/dev/null || true)"

  [[ -n "${state_line}" ]] || die "Resume contract failed: phase 1 state is unavailable on the server. Run a fresh deploy instead of --ts-ip."

  IFS=$'\t' read -r state_domain state_tunnel_mode <<< "${state_line}"
  [[ -n "${state_domain}" ]] || die "Resume contract failed: phase 1 state does not contain a domain. Run a fresh deploy instead of --ts-ip."
  [[ -n "${state_tunnel_mode}" ]] || state_tunnel_mode="false"

  if [[ "${state_domain}" != "${DOMAIN}" ]]; then
    die "Resume contract failed: --domain ${DOMAIN} does not match phase 1 state (${state_domain}). Run a fresh deploy."
  fi

  if [[ "${state_tunnel_mode}" != "${expected_tunnel_mode}" ]]; then
    die "Resume contract failed: --mode ${DEPLOY_MODE} does not match phase 1 state ($( [[ "${state_tunnel_mode}" == "true" ]] && printf 'tunnel' || printf 'standard' )). Run a fresh deploy."
  fi
}

wait_for_gate_c_timesync_remote() {
  local max_attempts="${1:-12}" delay="${2:-5}"
  local attempt synced_val waited=0

  for (( attempt=1; attempt<=max_attempts; attempt++ )); do
    synced_val="$(ssh_admin_sudo 'timedatectl show --property=NTPSynchronized --value 2>/dev/null || true' 2>/dev/null | tr -d '[:space:]')"
    if [[ "${synced_val}" == "yes" ]]; then
      (( waited == 1 )) && pass "Gate C pre-check: timesync synchronized"
      return 0
    fi
    [[ -n "${synced_val}" ]] || break
    if (( waited == 0 )); then
      log "Gate C pre-check: waiting for system clock synchronization..."
      waited=1
    fi
    (( attempt < max_attempts )) || break
    sleep "${delay}"
  done

  (( waited == 1 )) && warn "Gate C pre-check: timesync still not synchronized after $((max_attempts * delay))s; continuing to validator retries."
  return 1
}

verify_post_reboot_services_remote() {
  local gate_label="${1:-Gate B.5}"

  if ssh_admin_sudo 'systemctl is-active --quiet tailscaled.service'; then
    pass "${gate_label}: tailscaled.service is active"
  else
    fail "${gate_label}: tailscaled.service is not active"
    die "${gate_label} failed: tailscaled.service is not active after reboot."
  fi

  if ssh_admin_sudo 'ufw status 2>/dev/null | grep -q "^Status: active$"'; then
    pass "${gate_label}: UFW remains active"
  else
    fail "${gate_label}: UFW is not active"
    die "${gate_label} failed: UFW is not active after reboot."
  fi

  if ssh_admin_sudo 'systemctl is-active --quiet fail2ban.service'; then
    pass "${gate_label}: fail2ban.service is active"
  else
    fail "${gate_label}: fail2ban.service is not active"
    die "${gate_label} failed: fail2ban.service is not active after reboot."
  fi

  if ssh_admin_sudo 'fail2ban-client status sshd >/dev/null 2>&1'; then
    pass "${gate_label}: fail2ban sshd jail is active"
  else
    fail "${gate_label}: fail2ban sshd jail is not active"
    die "${gate_label} failed: fail2ban sshd jail is not active after reboot."
  fi

  if ssh_admin_sudo 'test "$(systemctl show docker.service --property=LoadState --value 2>/dev/null)" = loaded'; then
    if ssh_admin_sudo 'systemctl is-active --quiet docker.service'; then
      pass "${gate_label}: docker.service is active"
    else
      fail "${gate_label}: docker.service is not active"
      die "${gate_label} failed: docker.service is not active after reboot."
    fi
    verify_docker_user_gate_remote "${gate_label}"
  fi
}

phase2_gates() {
  step "2/5" "Gate checks (SSH transition to admin@tailscale)"

  # Gate A: SSH as admin via Tailscale IP using key auth
  log "Gate A: Testing SSH admin@${TS_IP} via key auth..."
  # (Gate A runs first so we know SSH works before syncing scripts)
  if wait_for_admin_ssh_or_die "Gate A (Tailscale peering may need time)" 6 10; then
    sync_operator_known_host_entries "${ADMIN_KNOWN_HOSTS}" "${TS_IP}"
    pass "Gate A: SSH ${ADMIN_USER}@${TS_IP} works"
  else
    fail "Gate A: Cannot SSH to ${ADMIN_USER}@${TS_IP} after retries"
    die "Gate A failed. Tailscale peering may not be established. Check 'tailscale status' on both machines."
  fi

  # Gate B: Verify admin identity
  local whoami_result
  whoami_result="$(ssh_admin 'whoami' 2>/dev/null | tr -d '[:space:]')"
  if [[ "${whoami_result}" == "${ADMIN_USER}" ]]; then
    pass "Gate B: whoami=${ADMIN_USER}"
  else
    fail "Gate B: Expected ${ADMIN_USER}, got '${whoami_result}'"
    die "Gate B failed."
  fi

  assert_resume_phase1_contract_remote

  # If package upgrades during hardening require a reboot, perform it here before Gate C.
  if ssh_admin_sudo 'test -f /run/reboot-required' >/dev/null 2>&1; then
    local reboot_pkgs reboot_drop_attempt
    reboot_pkgs="$(ssh_admin_sudo "tr '\n' ',' < /run/reboot-required.pkgs 2>/dev/null | sed 's/,$//'" 2>/dev/null || true)"
    warn "Gate B.5: Reboot required before validation (${reboot_pkgs:-unknown packages}). Rebooting now."

    ssh_admin_sudo 'nohup bash -c "sleep 1; systemctl reboot" >/dev/null 2>&1 &' || true

    # Wait for SSH to drop at least once to confirm reboot started.
    for (( reboot_drop_attempt=1; reboot_drop_attempt<=12; reboot_drop_attempt++ )); do
      if ! ssh_admin 'echo ok' >/dev/null 2>&1; then
        break
      fi
      sleep 5
    done

    if wait_for_admin_ssh_or_die "Gate B.5 reboot wait" 36 10; then
      if ssh_admin_sudo 'test ! -f /run/reboot-required' >/dev/null 2>&1; then
        pass "Gate B.5: Reboot completed and reboot-required cleared"
        verify_post_reboot_services_remote "Gate B.5"
      else
        die "Gate B.5 failed: server came back but /run/reboot-required still present."
      fi
    else
      die "Gate B.5 failed: server did not come back after reboot."
    fi
  fi

  # Clean up sensitive deploy.env left on server by phase 1.
  # Done here (not in phase 1) because post-hardening UFW blocks root SSH on the public IP.
  if ssh_admin_sudo "rm -f ${REMOTE_DEPLOY_ENV_PATH}" 2>/dev/null; then
    DEPLOY_ENV_REMOTE_PENDING="false"
  fi

  # Always re-sync companion scripts via admin SCP after Gate A/B confirm SSH works.
  # This ensures the latest versions are used even when phase 1 (root upload) was skipped.
  sync_companion_scripts

  # Resume safety: if Docker was already installed by a prior partial run, re-apply
  # hardening-owned Docker settings before Gate C validation. This keeps --ts-ip
  # resumes from failing on expected pre-phase3 drift.
  if ssh_admin_sudo 'docker version >/dev/null 2>&1'; then
    log "Gate C pre-check: Docker detected; reconciling daemon and bridge-SSH rules..."
    reconcile_docker_daemon_remote
    ssh_admin_sudo 'systemctl enable --now docker-user-hardening.service 2>/dev/null || true'
    ssh_admin_sudo 'systemctl start docker-ssh-cidr-sync.service 2>/dev/null || true'
  fi
  wait_for_gate_c_timesync_remote 12 5 || true

  # Gate C: Validation passes
  log "Gate C: Running base/validate.sh..."
  local validate_json gate_c_fail attempt max_attempts=6 delay=10
  for (( attempt=1; attempt<=max_attempts; attempt++ )); do
    validate_json="$(ssh_admin_sudo '/root/base/validate.sh --json --gate-c' 2>/dev/null)" || true
    gate_c_fail="$(jq -r '.fail // 999' 2>/dev/null <<< "${validate_json:-}" || echo "999")"
    if [[ "${gate_c_fail}" == "0" ]]; then
      report_validation_result "Gate C" "${validate_json}" \
        "Gate C failed. Fix validation failures before continuing."
      break
    fi
    if (( attempt < max_attempts )) && gate_c_failures_are_transient "${validate_json}"; then
      log "  Gate C transient failure (timesync/fail2ban/docker-user not ready yet); retrying in ${delay}s (${attempt}/${max_attempts})..."
      sleep "${delay}"
      continue
    fi
    report_validation_result "Gate C" "${validate_json}" \
      "Gate C failed. Fix validation failures before continuing."
  done
}

# ── Phase 3: Docker + Coolify ──────────────────────────────────────────────

paas_phase3_dispatch() {
  overlay_topo_sort "${PAAS}"
  coolify_phase3_docker_coolify_shared "$@"
}

paas_phase4_dispatch() {
  coolify_phase4_binding_dns_shared "$@"
}

paas_phase5_dispatch() {
  coolify_phase5_verify_shared "$@"
}

phase3_docker_coolify() {
  phase3_has_docker() { ssh_admin_sudo 'docker version >/dev/null 2>&1'; }
  phase3_install_docker() { coolify_install_docker_engine_script | ssh_admin_sudo 'bash -s'; }
  phase3_start_docker_user() { ssh_admin_sudo 'systemctl enable --now docker-user-hardening.service'; }
  phase3_verify_docker_user() { verify_docker_user_gate_remote "$1"; }
  phase3_has_coolify_env() {
    ssh_admin_sudo "bash -c 'test -f /data/coolify/source/.env && docker inspect coolify >/dev/null 2>&1'" >/dev/null 2>&1
  }
  phase3_install_coolify() { coolify_install_coolify_script | ssh_admin_sudo 'bash -s'; }
  phase3_reconcile_docker_daemon() { reconcile_docker_daemon_remote; }
  phase3_restart_docker_user() { ssh_admin_sudo 'systemctl restart docker-user-hardening.service'; }
  phase3_add_coolify_root_key() { coolify_add_coolify_root_key_script | ssh_admin_sudo 'bash -s'; }
  phase3_fix_host_docker_internal() { coolify_fix_host_docker_internal_script | ssh_admin_sudo 'bash -s'; }
  phase3_sync_docker_ssh_cidrs() { ssh_admin_sudo 'systemctl start docker-ssh-cidr-sync.service'; }

  # Gate D: Verify DOCKER-USER rules
  paas_phase3_dispatch \
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
  phase4_coolify_env_exists() { ssh_admin_sudo 'test -f /data/coolify/source/.env' >/dev/null 2>&1; }
  phase4_configure_binding() { ssh_admin_sudo "/root/overlays/coolify/configure_coolify_binding.sh --tailscale-ip ${TS_IP}"; }
  phase4_mark_binding_state() {
    {
      coolify_mark_bind_dashboard_state_script
      coolify_install_binding_guard_script
    } | ssh_admin_sudo 'bash -s'
  }
  phase4_set_wildcard_domain() {
    local app_domain_q
    app_domain_q="$(printf '%q' "${APP_DOMAIN}")"
    coolify_set_wildcard_domain_script | ssh_admin_sudo "APP_DOMAIN=${app_domain_q} bash -s"
  }
  phase4_reconcile_instance_settings() {
    local deploy_mode_q domain_q
    deploy_mode_q="$(printf '%q' "${DEPLOY_MODE}")"
    domain_q="$(printf '%q' "${DOMAIN}")"
    coolify_reconcile_instance_settings_script | ssh_admin_sudo "DEPLOY_MODE=${deploy_mode_q} DOMAIN=${domain_q} bash -s"
  }
  phase4_reconcile_pusher_env() {
    local deploy_mode_q ts_ip_q domain_q
    deploy_mode_q="$(printf '%q' "${DEPLOY_MODE}")"
    ts_ip_q="$(printf '%q' "${TS_IP}")"
    domain_q="$(printf '%q' "${DOMAIN}")"
    coolify_reconcile_pusher_env_script \
      | ssh_admin_sudo "DEPLOY_MODE=${deploy_mode_q} TS_IP=${ts_ip_q} DOMAIN=${domain_q} bash -s"
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
  phase4_stop_cloudflared() {
    ssh_admin_sudo 'systemctl disable --now cloudflared 2>/dev/null || systemctl stop cloudflared 2>/dev/null || true'
  }
  phase4_fetch_existing_tunnel() {
    ssh_admin_sudo 'bash -s' <<'EOF'
set -Eeuo pipefail
config="/etc/cloudflared/config.yml"
[[ -f "${config}" ]] || exit 0
tunnel_id="$(awk -F': *' '/^tunnel:/ {print $2; exit}' "${config}")"
[[ -n "${tunnel_id}" ]] || exit 0
creds_path="$(awk -F': *' '/^credentials-file:/ {print $2; exit}' "${config}")"
[[ -n "${creds_path}" ]] || creds_path="/etc/cloudflared/${tunnel_id}.json"
[[ -f "${creds_path}" ]] || exit 0
creds_id="$(jq -r '.TunnelID // empty' "${creds_path}")"
tunnel_secret="$(jq -r '.TunnelSecret // empty' "${creds_path}")"
[[ -n "${creds_id}" && "${creds_id}" == "${tunnel_id}" && -n "${tunnel_secret}" ]] || exit 0
printf '%s\t%s\n' "${creds_id}" "${tunnel_secret}"
EOF
  }
  phase4_configure_private_routes() {
    local domain_q resolver_q
    domain_q="$(printf '%q' "${DOMAIN}")"
    resolver_q="$(printf '%q' "$(private_tls_resolver_name)")"
    coolify_configure_private_dashboard_routes_script \
      | ssh_admin_sudo "DOMAIN=${domain_q} PRIVATE_TLS_RESOLVER=${resolver_q} bash -s"
  }
  phase4_configure_private_tls() {
    local cf_dns_token_q cf_zone_name_q resolver_q private_tls_ca_q zerossl_eab_kid_q zerossl_eab_hmac_q
    cf_dns_token_q="$(printf '%q' "${CF_API_TOKEN}")"
    cf_zone_name_q="$(printf '%q' "${CF_ZONE_NAME}")"
    local domain_q
    domain_q="$(printf '%q' "${DOMAIN}")"
    resolver_q="$(printf '%q' "$(private_tls_resolver_name)")"
    private_tls_ca_q="$(printf '%q' "${PRIVATE_TLS_CA}")"
    zerossl_eab_kid_q="$(printf '%q' "${ZEROSSL_EAB_KID}")"
    zerossl_eab_hmac_q="$(printf '%q' "${ZEROSSL_EAB_HMAC}")"
    coolify_configure_private_tls_dns_script \
      | ssh_admin_sudo "CF_DNS_API_TOKEN=${cf_dns_token_q} CF_ZONE_NAME=${cf_zone_name_q} DOMAIN=${domain_q} PRIVATE_TLS_RESOLVER=${resolver_q} PRIVATE_TLS_CA=${private_tls_ca_q} ZEROSSL_EAB_KID=${zerossl_eab_kid_q} ZEROSSL_EAB_HMAC=${zerossl_eab_hmac_q} bash -s"
  }
  phase4_remove_private_routes() {
    coolify_remove_private_dashboard_routes_script | ssh_admin_sudo 'bash -s'
  }
  phase4_restore_public_tls() {
    local domain_q cf_zone_name_q resolver_q
    domain_q="$(printf '%q' "${DOMAIN}")"
    cf_zone_name_q="$(printf '%q' "${CF_ZONE_NAME}")"
    resolver_q="$(printf '%q' "$(private_tls_resolver_name)")"
    coolify_restore_public_dashboard_tls_script \
      | ssh_admin_sudo "DOMAIN=${domain_q} CF_ZONE_NAME=${cf_zone_name_q} PRIVATE_TLS_RESOLVER=${resolver_q} bash -s"
  }

  # Contract anchors kept for tests/docs:
  # mode="${DEPLOY_MODE}"
  # PUSHER_HOST=ws.${DOMAIN}
  # coolify-private-dashboard.yaml
  # ws.${DOMAIN}
  paas_phase4_dispatch \
    phase4_coolify_env_exists \
    phase4_configure_binding \
    phase4_mark_binding_state \
    phase4_set_wildcard_domain \
    phase4_reconcile_instance_settings \
    phase4_reconcile_pusher_env \
    phase4_install_cloudflared \
    phase4_configure_cloudflared \
    phase4_stop_cloudflared \
    phase4_fetch_existing_tunnel \
    phase4_configure_private_routes \
    phase4_configure_private_tls \
    phase4_remove_private_routes \
    phase4_restore_public_tls
}

# ── Phase 5: Verification ─────────────────────────────────────────────────

phase5_fetch_validate_json() { ssh_admin_sudo '/root/base/validate.sh --json'; }
phase5_noop_operator_confirm() { :; }

phase5_verify() {
  # Contract anchors kept for docs/consistency checks:
  # Gate E: Checking dashboard accessibility...
  # Running final base/validate.sh...
  paas_phase5_dispatch phase5_fetch_validate_json external phase5_noop_operator_confirm
}

# ── Main ────────────────────────────────────────────────────────────────────

main() {
  run_report_init "${SCRIPT_NAME}"
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
  log "  Timezone:  ${SERVER_TIMEZONE}"
  log "  Local TZ:  $(local_tz_offset) (logs use UTC)"
  [[ "${DEPLOY_MODE}" == "tunnel" ]] && log "  Private TLS CA: ${PRIVATE_TLS_CA}"
  print_private_tls_ca_notice
  is_true "${PREFLIGHT_ONLY}" && log "  Mode:      preflight-only (no server changes)"
  [[ "${CF_TUNNEL_API_TOKEN}" != "${CF_API_TOKEN}" ]] && log "  CF tunnel token: custom"
  is_true "${SKIP_HARDEN}" && log "  TS IP:     ${TS_IP} (--ts-ip; skipping phase 1)"
  confirm "Proceed with deployment?"

  preflight
  if is_true "${PREFLIGHT_ONLY}"; then
    pass "Preflight-only checks completed. Exiting without deployment changes."
    return 0
  fi
  if is_true "${SKIP_HARDEN}"; then
    phase1_skipped
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
  trap 'deploy_exit_trap' EXIT
  main "$@"
fi
