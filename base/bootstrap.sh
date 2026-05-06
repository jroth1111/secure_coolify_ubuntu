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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_VERSION="1.2.8"
SCRIPT_NAME="$(basename "$0")"

# shellcheck source=../lib/tailscale.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../lib/tailscale.sh"
# shellcheck source=../overlays/docker-host/modules/cidrs.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../overlays/docker-host/modules/cidrs.sh"
# shellcheck source=../overlays/docker-host/modules/detect.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../overlays/docker-host/modules/detect.sh"
# shellcheck source=../overlays/docker-host/modules/readiness.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../overlays/docker-host/modules/readiness.sh"
# shellcheck source=../overlays/docker-host/modules/user_rules.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../overlays/docker-host/modules/user_rules.sh"
# shellcheck source=../overlays/docker-host/modules/daemon.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../overlays/docker-host/modules/daemon.sh"
# shellcheck source=../overlays/docker-host/modules/cidr_sync_timer.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../overlays/docker-host/modules/cidr_sync_timer.sh"
# shellcheck source=../overlays/docker-host/modules/ssh_match_dropin.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../overlays/docker-host/modules/ssh_match_dropin.sh"

# shellcheck source=./modules/os_detect.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/modules/os_detect.sh"
# shellcheck source=./modules/system.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/modules/system.sh"
# shellcheck source=./modules/bootloader.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/modules/bootloader.sh"
# shellcheck source=./modules/services.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/modules/services.sh"
# shellcheck source=./modules/kernel_sysctl.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/modules/kernel_sysctl.sh"
# shellcheck source=./modules/fail2ban.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/modules/fail2ban.sh"
# shellcheck source=./modules/ssh.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/modules/ssh.sh"
# shellcheck source=./modules/ssh_socket.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/modules/ssh_socket.sh"
# shellcheck source=./modules/password_policy.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/modules/password_policy.sh"
# shellcheck source=./modules/ufw.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/modules/ufw.sh"
# shellcheck source=./modules/rsyslog.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/modules/rsyslog.sh"
# shellcheck source=./modules/journald.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/modules/journald.sh"
# shellcheck source=./modules/auditd.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/modules/auditd.sh"
# shellcheck source=./modules/unattended.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/modules/unattended.sh"
# shellcheck source=./modules/post_checks.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/modules/post_checks.sh"
# shellcheck source=./modules/state.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/modules/state.sh"
# shellcheck source=./modules/validation_timer.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/modules/validation_timer.sh"

LOG_FILE="/var/log/bootstrap-hardening.log"
REPORT_FILE="/var/log/bootstrap-hardening-report.json"
STATE_DIR="/var/lib/bootstrap-hardening"
STATE_FILE="${STATE_DIR}/state"
STATE_LOCK_FILE="${STATE_FILE}.lock"
HOSTS_FILE="${HOSTS_FILE:-/etc/hosts}"

SSH_DROPIN_FILE="/etc/ssh/sshd_config.d/00-base-hardening.conf"
DOCKER_SSH_MATCH_DROPIN="/etc/ssh/sshd_config.d/15-docker-ssh-match.conf"
JOURNALD_DROPIN_FILE="/etc/systemd/journald.conf.d/90-coolify-persistent.conf"
AUDIT_RULES_FILE="/etc/audit/rules.d/60-coolify-baseline.rules"
AUDITD_CONF_FILE="/etc/audit/auditd.conf"
DOCKER_USER_SCRIPT="/usr/local/sbin/docker-user-hardening.sh"
DOCKER_USER_ENV_FILE="/etc/default/docker-user-hardening"
DOCKER_USER_UNIT_FILE="/etc/systemd/system/docker-user-hardening.service"
APT_AUTO_FILE="/etc/apt/apt.conf.d/20auto-upgrades"
APT_LOCAL_FILE="/etc/apt/apt.conf.d/52unattended-upgrades-local"
SYSCTL_DROPIN_FILE="/etc/sysctl.d/99-base-hardening.conf"
FAIL2BAN_JAIL_FILE="/etc/fail2ban/jail.d/coolify-hardening.local"
FAIL2BAN_LOCAL_FILE="/etc/fail2ban/fail2ban.local"
APPORT_DEFAULT_FILE="/etc/default/apport"
COOLIFY_BINDING_GUARD_SCRIPT="/usr/local/sbin/coolify-binding-guard.sh"
COOLIFY_BINDING_GUARD_SERVICE="/etc/systemd/system/coolify-binding-guard.service"
COOLIFY_BINDING_GUARD_TIMER="/etc/systemd/system/coolify-binding-guard.timer"
DOCKER_SSH_CIDR_SYNC_SCRIPT="/usr/local/sbin/docker-ssh-cidr-sync.sh"
DOCKER_SSH_CIDR_SYNC_SERVICE="/etc/systemd/system/docker-ssh-cidr-sync.service"
DOCKER_SSH_CIDR_SYNC_TIMER="/etc/systemd/system/docker-ssh-cidr-sync.timer"
CRON_EXTRA_OPTS_DROPIN="/etc/systemd/system/cron.service.d/10-extra-opts.conf"
NETWORKD_WAIT_ONLINE_DROPIN="/etc/systemd/system/systemd-networkd-wait-online.service.d/10-any-timeout.conf"

COOLIFY_ENV_FILE="/data/coolify/source/.env"

ADMIN_USER="${ADMIN_USER:-}"
ADMIN_PUBKEY="${ADMIN_PUBKEY:-}"
DOMAIN="${DOMAIN:-}"
TAILSCALE_CIDR="${TAILSCALE_CIDR:-100.64.0.0/10}"
SSH_PORT="${SSH_PORT:-22}"
WAN_IFACE="${WAN_IFACE:-}"
ENABLE_AUTO_REBOOT="${ENABLE_AUTO_REBOOT:-false}"
AUTO_REBOOT_TIME="${AUTO_REBOOT_TIME:-03:30}"
UPDATE_PROFILE="${UPDATE_PROFILE:-security-only}"
JOURNAL_RETENTION="${JOURNAL_RETENTION:-3month}"
JOURNAL_MAX_USE="${JOURNAL_MAX_USE:-2G}"
TUNNEL_MODE="${TUNNEL_MODE:-false}"
SWAP_SIZE="${SWAP_SIZE:-2G}"
TIMEZONE="${TIMEZONE:-UTC}"
DRY_RUN="${DRY_RUN:-false}"
FORCE="${FORCE:-false}"
UPGRADE_MAIL="${UPGRADE_MAIL:-}"
BIND_DASHBOARD_TO_TAILSCALE="${BIND_DASHBOARD_TO_TAILSCALE:-false}"
INSTALL_TAILSCALE="${INSTALL_TAILSCALE:-false}"
TAILSCALE_AUTH_KEY="${TAILSCALE_AUTH_KEY:-}"
TAILSCALE_DIRECT_WAN="${TAILSCALE_DIRECT_WAN:-false}"
STRICT_DOCKER_SSH_CIDRS="${STRICT_DOCKER_SSH_CIDRS:-true}"
INSECURE_ENV="${INSECURE_ENV:-false}"
DOCKER_NPROC_HARD="${DOCKER_NPROC_HARD:-8192}"
DOCKER_NPROC_SOFT="${DOCKER_NPROC_SOFT:-4096}"
ALLOWED_PRIVILEGED_CONTAINERS="${ALLOWED_PRIVILEGED_CONTAINERS:-}"

OS_VERSION=""
DOCKER_PRESENT="false"
DOCKER_RULES_APPLIED="false"
DOCKER_DAEMON_NEEDS_RESTART="false"
declare -a DOCKER_SSH_CIDRS=()

log() {
  printf '[%s] %s\n' "$(date -Iseconds)" "$*"
}

warn() {
  log "WARN: $*"
}

die() {
  log "ERROR: $*"
  exit 1
}

on_err() {
  local line_no="$1"
  local cmd="$2"
  log "ERROR: command failed at line ${line_no}: ${cmd}"
}

trap 'on_err "${LINENO}" "${BASH_COMMAND}"' ERR

is_true() {
  case "${1,,}" in
    1|true|yes|y|on) return 0 ;;
    *) return 1 ;;
  esac
}

require_value() {
  local opt="$1"
  local val="${2:-}"
  [[ -n "${val}" ]] || die "Option ${opt} requires a value."
}

usage() {
  cat <<'EOF'
Ubuntu Coolify bootstrap hardening script.

Usage:
  base/bootstrap.sh --admin-user <name> --admin-pubkey "<ssh key>" [options]

Required:
  --admin-user <name>           Admin user to create/ensure and allow via SSH
  --admin-pubkey "<ssh key>"    SSH public key to add for admin user

Optional:
  --domain <fqdn>               Dashboard domain for private-hostname /etc/hosts normalization
  --tailscale-cidr <cidr>       Tailscale CIDR hint (default: 100.64.0.0/10)
  --ssh-port <port>             SSH port (default: 22)
  --wan-iface <iface>           WAN interface (default: auto-detected)
  --tunnel-mode                 Skip WAN 80/443 rules (Cloudflare Tunnel / outbound-only)
  --swap-size <size>            Swap file size (default: 2G; format: <N>G or <N>M; 0 to skip)
  --timezone <IANA>             System timezone (default: UTC)
  --enable-auto-reboot <bool>   Enable unattended-upgrades reboot (default: false)
  --auto-reboot-time <HH:MM>    Reboot time for unattended-upgrades (default: 03:30)
  --update-profile <name>       unattended-upgrades profile: security-only|balanced (default: security-only)
  --journal-retention <span>   Journal retention period (default: 3month)
  --strict-docker-ssh-cidrs   Use discovered Docker bridge CIDRs for SSH/UFW (default)
  --compat-docker-ssh-cidrs   Use broad compatibility ranges (10.0.0.0/8, 172.16.0.0/12)
  --docker-nproc-hard <num>   Docker default nproc hard limit (default: 8192)
  --docker-nproc-soft <num>   Docker default nproc soft limit (default: 4096)
  --allowed-privileged-containers <csv> Comma-separated privileged container names allowed by policy
  --bind-dashboard-to-tailscale Bind Coolify dashboard to Tailscale IP only (split-horizon)
  --install-tailscale           Install Tailscale if not present (requires --tailscale-auth-key or interactive)
  --tailscale-auth-key <key>    Tailscale auth key for non-interactive setup (use with --install-tailscale)
  --tailscale-direct-wan        Allow WAN UDP 41641 for direct Tailscale paths (optional optimization)
  --no-tailscale-direct-wan     Keep WAN UDP 41641 closed (default; DERP fallback remains available)
  --upgrade-mail <address>      Email for unattended-upgrade failure reports (optional)
  --env-file <path>             Source variables from file before parsing flags
  --insecure-env                Allow env file with insecure permissions (dangerous; for automation only)
  --dry-run                     Print actions without changing system
  --force                       Override non-Tailscale SSH-session safety gate
  -h, --help                    Show this help

Environment variables are also supported for all options above.
Env-file uses the same variable names (ADMIN_USER, SSH_PORT, TUNNEL_MODE, etc.).
CLI flags override env-file values.

Dashboard Tailscale Restriction (--bind-dashboard-to-tailscale):
  Verifies and re-applies UFW rules restricting Coolify dashboard (port 8000), Soketi
  (port 6001), and terminal (port 6002) to the tailscale0 interface only, then installs
  a watchdog timer that periodically re-applies them if removed. UFW rules on tailscale0
  are always configured by the hardening step; this flag adds a periodic verification
  layer on top.
EOF
}

run() {
  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: $*"
    return 0
  fi
  "$@"
}

write_file() {
  local path="$1"
  local mode="$2"
  local owner="$3"
  local group="$4"
  local tmp

  tmp="$(mktemp)"
  cat > "${tmp}"

  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: write ${path}"
    rm -f "${tmp}"
    return 0
  fi

  install -d -m 0755 "$(dirname "${path}")"
  install -m "${mode}" -o "${owner}" -g "${group}" "${tmp}" "${path}"
  rm -f "${tmp}"
}

trim_whitespace() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "${value}"
}

unescape_backslash_sequences() {
  local raw="$1"
  local out="" char
  local i=0
  while (( i < ${#raw} )); do
    char="${raw:i:1}"
    if [[ "${char}" == "\\" && $((i + 1)) -lt ${#raw} ]]; then
      i=$((i + 1))
      out+="${raw:i:1}"
    else
      out+="${char}"
    fi
    i=$((i + 1))
  done
  printf '%s' "${out}"
}

env_file_key_supported() {
  case "$1" in
    ADMIN_USER|ADMIN_PUBKEY|DOMAIN|TAILSCALE_CIDR|SSH_PORT|WAN_IFACE|ENABLE_AUTO_REBOOT|AUTO_REBOOT_TIME|UPDATE_PROFILE|JOURNAL_RETENTION|JOURNAL_MAX_USE|TUNNEL_MODE|SWAP_SIZE|TIMEZONE|DRY_RUN|FORCE|UPGRADE_MAIL|BIND_DASHBOARD_TO_TAILSCALE|INSTALL_TAILSCALE|TAILSCALE_AUTH_KEY|TAILSCALE_DIRECT_WAN|STRICT_DOCKER_SSH_CIDRS|INSECURE_ENV|DOCKER_NPROC_HARD|DOCKER_NPROC_SOFT|ALLOWED_PRIVILEGED_CONTAINERS)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

set_env_file_value() {
  local key="$1"
  local value="$2"
  case "${key}" in
    ADMIN_USER|ADMIN_PUBKEY|DOMAIN|TAILSCALE_CIDR|SSH_PORT|WAN_IFACE|ENABLE_AUTO_REBOOT|AUTO_REBOOT_TIME|UPDATE_PROFILE|JOURNAL_RETENTION|JOURNAL_MAX_USE|TUNNEL_MODE|SWAP_SIZE|TIMEZONE|DRY_RUN|FORCE|UPGRADE_MAIL|BIND_DASHBOARD_TO_TAILSCALE|INSTALL_TAILSCALE|TAILSCALE_AUTH_KEY|TAILSCALE_DIRECT_WAN|STRICT_DOCKER_SSH_CIDRS|INSECURE_ENV|DOCKER_NPROC_HARD|DOCKER_NPROC_SOFT|ALLOWED_PRIVILEGED_CONTAINERS)
      printf -v "${key}" '%s' "${value}"
      ;;
    *)
      die "Internal error: unsupported env key assignment '${key}'"
      ;;
  esac
}

decode_env_file_value() {
  local raw="$1"
  local decoded

  raw="$(trim_whitespace "${raw}")"
  if [[ -z "${raw}" ]]; then
    printf ''
    return 0
  fi

  if [[ "${raw}" == \"* ]]; then
    [[ "${raw}" == *\" ]] || return 1
    decoded="${raw:1:${#raw}-2}"
    unescape_backslash_sequences "${decoded}"
    return 0
  fi

  if [[ "${raw}" == \'* ]]; then
    [[ "${raw}" == *\' ]] || return 1
    decoded="${raw:1:${#raw}-2}"
    printf '%s' "${decoded}"
    return 0
  fi

  if [[ "${raw}" == *\"* || "${raw}" == *\'* ]]; then
    return 1
  fi

  # Supports legacy deploy files that used shell-style backslash escaping.
  unescape_backslash_sequences "${raw}"
}

load_env_file_safely() {
  local env_file="$1"
  local line trimmed key raw value
  local lineno=0

  while IFS= read -r line || [[ -n "${line}" ]]; do
    lineno=$((lineno + 1))
    line="${line%$'\r'}"
    trimmed="$(trim_whitespace "${line}")"
    [[ -z "${trimmed}" || "${trimmed}" == \#* ]] && continue

    if [[ "${trimmed}" == export[[:space:]]* ]]; then
      trimmed="$(trim_whitespace "${trimmed#export}")"
    fi

    if [[ ! "${trimmed}" =~ ^([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=(.*)$ ]]; then
      die "Invalid env file syntax at ${env_file}:${lineno} (expected KEY=VALUE)"
    fi
    key="${BASH_REMATCH[1]}"
    raw="${BASH_REMATCH[2]}"

    env_file_key_supported "${key}" || die "Unsupported env key '${key}' in ${env_file}:${lineno}"

    if ! value="$(decode_env_file_value "${raw}")"; then
      die "Invalid env value for '${key}' in ${env_file}:${lineno}"
    fi
    set_env_file_value "${key}" "${value}"
  done < "${env_file}"
}

parse_args() {
  # Pre-scan for --env-file to source it before parsing other args
  local env_file=""
  local insecure_env_cli="false"
  local arg
  for arg in "$@"; do
    if [[ "${arg}" == --env-file=* ]]; then
      env_file="${arg#--env-file=}"
    fi
    if [[ "${arg}" == "--insecure-env" ]]; then
      insecure_env_cli="true"
    fi
  done
  if [[ -z "${env_file}" ]]; then
    local prev=""
    for arg in "$@"; do
      if [[ "${prev}" == "--env-file" ]]; then
        env_file="${arg}"
      fi
      if [[ "${arg}" == "--insecure-env" ]]; then
        insecure_env_cli="true"
      fi
      prev="${arg}"
    done
  fi
  if [[ -n "${env_file}" ]]; then
    [[ -f "${env_file}" ]] || die "Env file not found: ${env_file}"
    local file_perms
    file_perms="$(stat -c '%a' "${env_file}" 2>/dev/null || stat -f '%Lp' "${env_file}" 2>/dev/null || echo "unknown")"
    if [[ "${file_perms}" != "unknown" && "${file_perms}" != "600" && "${file_perms}" != "400" ]]; then
      # --insecure-env can be supplied as an env var or CLI flag; CLI pre-scan is needed
      # because env-file is sourced before full argument parsing.
      if is_true "${INSECURE_ENV}" || is_true "${insecure_env_cli}"; then
        warn "--insecure-env used: proceeding with env file ${env_file} permissions ${file_perms}"
      else
        die "Env file ${env_file} has permissions ${file_perms}; refusing to proceed (requires 0600 or 0400). Fix with: chmod 600 \"${env_file}\" or chmod 400 \"${env_file}\". Use --insecure-env only when unavoidable."
      fi
    fi
    load_env_file_safely "${env_file}"
  fi

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --env-file)
        # Already processed in pre-scan; consume and skip
        require_value "$1" "${2:-}"
        shift 2
        ;;
      --env-file=*)
        # Already processed in pre-scan; skip
        shift
        ;;
      --admin-user)
        require_value "$1" "${2:-}"
        ADMIN_USER="$2"
        shift 2
        ;;
      --admin-pubkey)
        require_value "$1" "${2:-}"
        ADMIN_PUBKEY="$2"
        shift 2
        ;;
      --domain)
        require_value "$1" "${2:-}"
        DOMAIN="$2"
        shift 2
        ;;
      --tailscale-cidr)
        require_value "$1" "${2:-}"
        TAILSCALE_CIDR="$2"
        shift 2
        ;;
      --ssh-port)
        require_value "$1" "${2:-}"
        SSH_PORT="$2"
        shift 2
        ;;
      --wan-iface)
        require_value "$1" "${2:-}"
        WAN_IFACE="$2"
        shift 2
        ;;
      --enable-auto-reboot)
        require_value "$1" "${2:-}"
        ENABLE_AUTO_REBOOT="$2"
        shift 2
        ;;
      --auto-reboot-time)
        require_value "$1" "${2:-}"
        AUTO_REBOOT_TIME="$2"
        shift 2
        ;;
      --update-profile)
        require_value "$1" "${2:-}"
        UPDATE_PROFILE="$2"
        shift 2
        ;;
      --journal-retention)
        require_value "$1" "${2:-}"
        JOURNAL_RETENTION="$2"
        shift 2
        ;;
      --strict-docker-ssh-cidrs)
        STRICT_DOCKER_SSH_CIDRS="true"
        shift
        ;;
      --compat-docker-ssh-cidrs)
        STRICT_DOCKER_SSH_CIDRS="false"
        shift
        ;;
      --docker-nproc-hard)
        require_value "$1" "${2:-}"
        DOCKER_NPROC_HARD="$2"
        shift 2
        ;;
          --insecure-env)
        INSECURE_ENV="true"
        shift
        ;;
      --docker-nproc-soft)
        require_value "$1" "${2:-}"
        DOCKER_NPROC_SOFT="$2"
        shift 2
        ;;
      --allowed-privileged-containers)
        require_value "$1" "${2:-}"
        ALLOWED_PRIVILEGED_CONTAINERS="$2"
        shift 2
        ;;
      --swap-size)
        require_value "$1" "${2:-}"
        SWAP_SIZE="$2"
        shift 2
        ;;
      --timezone)
        require_value "$1" "${2:-}"
        TIMEZONE="$2"
        shift 2
        ;;
      --tunnel-mode)
        TUNNEL_MODE="true"
        shift
        ;;
      --bind-dashboard-to-tailscale)
        BIND_DASHBOARD_TO_TAILSCALE="true"
        shift
        ;;
      --install-tailscale)
        INSTALL_TAILSCALE="true"
        shift
        ;;
      --tailscale-auth-key)
        require_value "$1" "${2:-}"
        TAILSCALE_AUTH_KEY="$2"
        shift 2
        ;;
      --tailscale-direct-wan)
        TAILSCALE_DIRECT_WAN="true"
        shift
        ;;
      --no-tailscale-direct-wan)
        TAILSCALE_DIRECT_WAN="false"
        shift
        ;;
      --dry-run)
        DRY_RUN="true"
        shift
        ;;
      --force)
        FORCE="true"
        shift
        ;;
      --upgrade-mail)
        require_value "$1" "${2:-}"
        UPGRADE_MAIL="$2"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "Unknown option: $1 (use --help)"
        ;;
    esac
  done
}

setup_logging() {
  if is_true "${DRY_RUN}"; then
    log "Dry-run enabled; no host changes will be applied."
    return 0
  fi

  # Keep /var/log non-world-accessible while allowing rsyslog (group: syslog)
  # to create missing active targets.
  if getent group syslog >/dev/null 2>&1; then
    install -d -m 0770 -o root -g syslog /var/log
  else
    install -d -m 0750 /var/log
    warn "Group 'syslog' not found; using fallback /var/log mode 0750."
  fi
  touch "${LOG_FILE}"
  chmod 0600 "${LOG_FILE}"
  exec > >(tee -a "${LOG_FILE}") 2>&1
}

require_root() {
  [[ "$(id -u)" -eq 0 ]] || die "Run as root."
}

validate_pubkey() {
  printf '%s\n' "${ADMIN_PUBKEY}" | awk '
    $1 ~ /^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com)$/ && NF >= 2 { ok=1 }
    END { exit(ok ? 0 : 1) }
  ' || die "ADMIN_PUBKEY does not look like a valid SSH public key."
}

validate_inputs() {
  [[ -n "${ADMIN_USER}" ]] || die "Missing ADMIN_USER / --admin-user."
  [[ -n "${ADMIN_PUBKEY}" ]] || die "Missing ADMIN_PUBKEY / --admin-pubkey."
  [[ "${ADMIN_USER}" != "root" ]] || die "ADMIN_USER must not be root."
  [[ "${ADMIN_USER}" =~ ^[a-z_][a-z0-9_-]*[$]?$ ]] || die "ADMIN_USER is not a valid Linux username."
  [[ "${SSH_PORT}" =~ ^[0-9]+$ ]] || die "SSH_PORT must be numeric."
  (( SSH_PORT >= 1 && SSH_PORT <= 65535 )) || die "SSH_PORT must be in range 1..65535."
  [[ "${AUTO_REBOOT_TIME}" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] || die "AUTO_REBOOT_TIME must be HH:MM (24h)."

  # Validate ENABLE_AUTO_REBOOT is either true or false (or recognized variant)
  local reboot_lower="${ENABLE_AUTO_REBOOT,,}"
  if [[ "${reboot_lower}" != "true" && "${reboot_lower}" != "false" && "${reboot_lower}" != "1" && "${reboot_lower}" != "0" && "${reboot_lower}" != "yes" && "${reboot_lower}" != "no" ]]; then
    die "ENABLE_AUTO_REBOOT must be true/false (got: ${ENABLE_AUTO_REBOOT})."
  fi

  local strict_cidrs_lower="${STRICT_DOCKER_SSH_CIDRS,,}"
  if [[ "${strict_cidrs_lower}" != "true" && "${strict_cidrs_lower}" != "false" && "${strict_cidrs_lower}" != "1" && "${strict_cidrs_lower}" != "0" && "${strict_cidrs_lower}" != "yes" && "${strict_cidrs_lower}" != "no" ]]; then
    die "STRICT_DOCKER_SSH_CIDRS must be true/false (got: ${STRICT_DOCKER_SSH_CIDRS})."
  fi

  [[ "${DOCKER_NPROC_HARD}" =~ ^[1-9][0-9]*$ ]] || die "DOCKER_NPROC_HARD must be a positive integer."
  [[ "${DOCKER_NPROC_SOFT}" =~ ^[1-9][0-9]*$ ]] || die "DOCKER_NPROC_SOFT must be a positive integer."
  (( DOCKER_NPROC_SOFT <= DOCKER_NPROC_HARD )) || die "DOCKER_NPROC_SOFT must be <= DOCKER_NPROC_HARD."

  local tailscale_direct_wan_lower="${TAILSCALE_DIRECT_WAN,,}"
  if [[ "${tailscale_direct_wan_lower}" != "true" && "${tailscale_direct_wan_lower}" != "false" && "${tailscale_direct_wan_lower}" != "1" && "${tailscale_direct_wan_lower}" != "0" && "${tailscale_direct_wan_lower}" != "yes" && "${tailscale_direct_wan_lower}" != "no" ]]; then
    die "TAILSCALE_DIRECT_WAN must be true/false (got: ${TAILSCALE_DIRECT_WAN})."
  fi

  case "${UPDATE_PROFILE}" in
    security-only|balanced) ;;
    *) die "UPDATE_PROFILE must be one of: security-only, balanced (got: ${UPDATE_PROFILE})." ;;
  esac

  [[ "${JOURNAL_RETENTION}" =~ ^[0-9]+(us(ec)?|ms(ec)?|s(ec(ond)?s?)?|m(in(ute)?s?)?|h(our)?s?|d(ay)?s?|w(eek)?s?|month?s?|y(ear)?s?)$ ]] \
    || die "JOURNAL_RETENTION must be a valid systemd time span (e.g. 3month, 4w, 90d)."

  if [[ "${SWAP_SIZE}" != "0" ]]; then
    [[ "${SWAP_SIZE}" =~ ^[0-9]+[GgMm]$ ]] || die "SWAP_SIZE must be <N>G or <N>M (e.g. 2G, 512M), or 0 to skip."
  fi

  [[ "${TIMEZONE}" =~ ^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*$ ]] \
    || die "TIMEZONE must be an IANA timezone name (for example: Australia/Melbourne or UTC)."
  [[ -e "/usr/share/zoneinfo/${TIMEZONE}" ]] \
    || die "TIMEZONE '${TIMEZONE}' not found under /usr/share/zoneinfo."

  if [[ -n "${DOMAIN}" ]]; then
    [[ "${DOMAIN}" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$ && "${DOMAIN}" == *.* && "${DOMAIN}" != *..* ]] \
      || die "DOMAIN must be a valid FQDN (got: ${DOMAIN})."
  fi

  # Validate split-horizon binding options
  if is_true "${BIND_DASHBOARD_TO_TAILSCALE}" && ! is_true "${DRY_RUN}"; then
    [[ -f "${COOLIFY_ENV_FILE}" ]] \
      || die "Coolify .env not found at ${COOLIFY_ENV_FILE}. Is Coolify installed?"
    command -v docker >/dev/null 2>&1 \
      || die "--bind-dashboard-to-tailscale requires Docker."
    docker compose version >/dev/null 2>&1 \
      || die "--bind-dashboard-to-tailscale requires the Docker Compose plugin."
    [[ -d "/data/coolify/source" ]] \
      || die "--bind-dashboard-to-tailscale requires /data/coolify/source to exist."
  fi

  # Validate Tailscale install options
  if is_true "${INSTALL_TAILSCALE}"; then
    # If Tailscale is not already installed and no auth key provided, warn about interactive mode
    if ! command -v tailscale >/dev/null 2>&1 && [[ -z "${TAILSCALE_AUTH_KEY}" ]]; then
      warn "INSTALL_TAILSCALE is set but TAILSCALE_AUTH_KEY not provided. Interactive auth required."
    fi
  fi

  validate_pubkey
}

















configure_coolify_binding_watchdog() {
  if ! is_true "${BIND_DASHBOARD_TO_TAILSCALE}"; then
    return 0
  fi

  write_file "${COOLIFY_BINDING_GUARD_SCRIPT}" "0750" "root" "root" <<'GUARD_EOF'
#!/usr/bin/env bash
# Coolify dashboard UFW binding guard.
# Verifies that UFW rules restricting the Coolify dashboard (port 8000), Soketi
# (port 6001), and terminal (port 6002) to the tailscale0 interface exist, and
# re-applies them if missing.
# Does NOT modify Coolify's .env — security is enforced entirely by UFW.
set -Euo pipefail

TAILSCALE_IFACE="tailscale0"
LOG_TAG="coolify-binding-guard"

log() { logger -t "${LOG_TAG}" -- "$*"; }

command -v ufw >/dev/null 2>&1 || { log "ufw not found; skipping."; exit 0; }

ufw_status="$(ufw status 2>/dev/null | head -1)" || true
[[ "${ufw_status}" == "Status: active" ]] || { log "UFW not active; skipping."; exit 0; }

changed=false

# Check and re-apply UFW rule for port 8000 on tailscale0
if ! ufw status | grep -q "8000.*on ${TAILSCALE_IFACE}"; then
  log "UFW rule for port 8000 on ${TAILSCALE_IFACE} missing — re-applying."
  ufw allow in on "${TAILSCALE_IFACE}" proto tcp to any port 8000 \
    comment "coolify-hardening-dashboard-tailscale" 2>/dev/null || true
  changed=true
fi

# Check and re-apply UFW rule for port 6001 on tailscale0
if ! ufw status | grep -q "6001.*on ${TAILSCALE_IFACE}"; then
  log "UFW rule for port 6001 on ${TAILSCALE_IFACE} missing — re-applying."
  ufw allow in on "${TAILSCALE_IFACE}" proto tcp to any port 6001 \
    comment "coolify-hardening-soketi-tailscale" 2>/dev/null || true
  changed=true
fi

# Check and re-apply UFW rule for port 6002 on tailscale0
if ! ufw status | grep -q "6002.*on ${TAILSCALE_IFACE}"; then
  log "UFW rule for port 6002 on ${TAILSCALE_IFACE} missing — re-applying."
  ufw allow in on "${TAILSCALE_IFACE}" proto tcp to any port 6002 \
    comment "coolify-hardening-terminal-tailscale" 2>/dev/null || true
  changed=true
fi

if "${changed}"; then
  log "UFW rules re-applied for ports 8000, 6001, and 6002 on ${TAILSCALE_IFACE}."
else
  log "UFW rules for ports 8000, 6001, and 6002 on ${TAILSCALE_IFACE} are present — no action needed."
fi
GUARD_EOF

  write_file "${COOLIFY_BINDING_GUARD_SERVICE}" "0644" "root" "root" <<'UNIT_EOF'
[Unit]
Description=Verify Coolify dashboard UFW rules on tailscale0 are present
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/coolify-binding-guard.sh
UNIT_EOF

  write_file "${COOLIFY_BINDING_GUARD_TIMER}" "0644" "root" "root" <<'TIMER_EOF'
[Unit]
Description=Periodically verify Coolify dashboard UFW rules on tailscale0

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=30s

[Install]
WantedBy=timers.target
TIMER_EOF

  run systemctl daemon-reload
  run systemctl enable --now coolify-binding-guard.timer
  log "Coolify binding watchdog enabled (checks every 5 minutes)."
}

configure_coolify_binding() {
  if ! is_true "${BIND_DASHBOARD_TO_TAILSCALE}"; then
    return 0
  fi

  # Dashboard Tailscale restriction is enforced via UFW, not APP_PORT socket binding.
  # Coolify's docker-compose.prod.yml uses APP_PORT in both ports: and expose: directives;
  # expose: requires a plain port number, so IP:port format is incompatible and breaks
  # Coolify container startup. UFW default-deny + explicit allow on tailscale0 provides
  # equivalent defense-in-depth without touching Coolify's configuration.
  #
  # UFW rules for 8000/6001 on tailscale0 are already applied by configure_ufw(); this
  # function verifies they exist and re-applies them idempotently.

  log "Verifying Coolify dashboard UFW rules on ${TAILSCALE_IFACE}..."

  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: would verify UFW rules for ports 8000, 6001, and 6002 on ${TAILSCALE_IFACE}"
    log "DRY-RUN: would verify port 8000 is listening; external exposure is validated from off-host"
    return 0
  fi

  if command -v ufw >/dev/null 2>&1; then
    # Idempotent — ufw silently skips duplicate rules
    local ufw_result ufw_ok=true
    ufw_result="$(ufw allow in on "${TAILSCALE_IFACE}" proto tcp to any port 8000 \
      comment "coolify-hardening-dashboard-tailscale" 2>&1)" || {
      warn "UFW rule for port 8000 on ${TAILSCALE_IFACE} failed: ${ufw_result}"
      ufw_ok=false
    }
    ufw_result="$(ufw allow in on "${TAILSCALE_IFACE}" proto tcp to any port 6001 \
      comment "coolify-hardening-soketi-tailscale" 2>&1)" || {
      warn "UFW rule for port 6001 on ${TAILSCALE_IFACE} failed: ${ufw_result}"
      ufw_ok=false
    }
    ufw_result="$(ufw allow in on "${TAILSCALE_IFACE}" proto tcp to any port 6002 \
      comment "coolify-hardening-terminal-tailscale" 2>&1)" || {
      warn "UFW rule for port 6002 on ${TAILSCALE_IFACE} failed: ${ufw_result}"
      ufw_ok=false
    }
    is_true "${ufw_ok}" && log "UFW rules verified for ports 8000, 6001, and 6002 on ${TAILSCALE_IFACE}."
  else
    warn "ufw not found — skipping UFW rule verification."
  fi

  # Wait for Coolify to bind port 8000 (up to 30s)
  log "Waiting for Coolify to bind port 8000 (up to 30s)..."
  local i
  for (( i = 1; i <= 6; i++ )); do
    if ss -tlnp 2>/dev/null | grep -q ':8000 '; then
      break
    fi
    sleep 5
  done

  # Verify port 8000 is listening
  local bound_8000
  bound_8000="$(ss -tlnp 2>/dev/null | grep ':8000 ' || true)"
  if [[ -n "${bound_8000}" ]]; then
    log "PASS: Port 8000 is listening"
  else
    warn "Port 8000 not yet listening. Check: ss -tlnp | grep 8000"
  fi

  log "Coolify dashboard UFW restriction verified. External exposure is validated from off-host."
}














































main() {
  parse_args "$@"
  require_root
  setup_logging

  log "Starting ${SCRIPT_NAME} v${SCRIPT_VERSION}"
  warn_on_state_version_mismatch
  validate_inputs
  detect_os
  check_disk_space

  ssh_session_safety_gate

  log "Configuring system timezone (${TIMEZONE})."
  configure_timezone

  log "Normalizing private hostname loopback overrides."
  normalize_private_hosts_file

  log "Verifying NTP time synchronization."
  ensure_timesync

  detect_wan_iface
  ensure_packages
  ensure_bootloader_embed_safety
  configure_networkd_wait_online
  configure_cron_extra_opts
  ensure_power_group

  # Install Tailscale if requested (before verify_tailscale_iface)
  if is_true "${INSTALL_TAILSCALE}"; then
    log "Installing Tailscale."
    install_tailscale
  fi

  require_commands
  ensure_tailscaled_notify_access
  verify_tailscale_iface
  ensure_tailscale_ssh_disabled
  emit_tailscale_result_sentinel
  apply_system_package_updates
  detect_docker
  discover_docker_ssh_cidrs

  log "Configuring swap."
  configure_swap

  log "Disabling unused network services."
  disable_unused_services

  log "Applying login banner."
  configure_banner

  log "Applying account and SSH hardening."
  ensure_admin_access
  configure_ssh
  configure_docker_ssh_match_dropin
  configure_ssh_socket
  configure_password_policy

  log "Applying auditd baseline."
  configure_auditd

  log "Disabling apport crash reporting service."
  configure_apport

  log "Applying sysctl kernel hardening."
  configure_sysctl

  log "Applying Docker daemon log rotation."
  configure_docker_daemon

  log "Applying DOCKER-USER hardening assets."
  configure_docker_user

  log "Applying UFW baseline."
  configure_ufw

  log "Applying rsyslog target/logrotate safety."
  configure_rsyslog_targets

  if is_true "${DOCKER_DAEMON_NEEDS_RESTART}"; then
    log "Restarting Docker (deferred from daemon.json update, DOCKER-USER rules already applied)."
    run systemctl restart docker
    if [[ "${DOCKER_PRESENT}" == "true" ]]; then
      ensure_docker_user_service_applied "Docker restart"
    fi
    rm -f "${DOCKER_DAEMON_JSON}".bak.*
  fi

  log "Applying fail2ban."
  configure_fail2ban

  log "Applying journald persistence."
  configure_journald

  log "Applying unattended-upgrades policy."
  configure_unattended_upgrades
  log "Installing hardening validation timer."
  configure_hardening_validation_timer

  # Configure Coolify split-horizon binding if requested
  if is_true "${BIND_DASHBOARD_TO_TAILSCALE}"; then
    log "Configuring Coolify split-horizon binding."
    configure_coolify_binding
    log "Installing Coolify binding watchdog."
    configure_coolify_binding_watchdog
  fi

  write_state
  configure_docker_ssh_cidr_sync_timer

  log "Running post-apply checks."
  run_post_checks

  # Ensure DETECTED_TAILSCALE_IP is populated for generate_report() regardless of
  # --bind-dashboard-to-tailscale (get_tailscale_ip only runs inside configure_coolify_binding
  # which is skipped when binding is not requested). Do this BEFORE generate_report.
  if [[ -z "${DETECTED_TAILSCALE_IP}" ]]; then
    get_tailscale_ip >/dev/null 2>&1 || true
  fi

  generate_report
  log "Completed hardening bootstrap successfully."

  # Print Tailscale IP on stdout for orchestrators (deploy.sh) to capture.
  # Post-hardening, UFW blocks all SSH on the public IP (tailscale0 only), so
  # the orchestrator cannot run 'tailscale ip -4' via a new root SSH session.
  local _ts_ip_final=""
  _ts_ip_final="$(tailscale ip -4 2>/dev/null || true)"
  if [[ -n "${_ts_ip_final}" ]]; then
    printf 'HARDEN_RESULT_TAILSCALE_IP=%s\n' "${_ts_ip_final}"
  fi
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
