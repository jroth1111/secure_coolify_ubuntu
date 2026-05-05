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

# shellcheck source=lib/tailscale.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/tailscale.sh"

LOG_FILE="/var/log/bootstrap-hardening.log"
REPORT_FILE="/var/log/bootstrap-hardening-report.json"
STATE_DIR="/var/lib/bootstrap-hardening"
STATE_FILE="${STATE_DIR}/state"
STATE_LOCK_FILE="${STATE_FILE}.lock"
HOSTS_FILE="${HOSTS_FILE:-/etc/hosts}"

SSH_DROPIN_FILE="/etc/ssh/sshd_config.d/00-coolify-hardening.conf"
JOURNALD_DROPIN_FILE="/etc/systemd/journald.conf.d/90-coolify-persistent.conf"
AUDIT_RULES_FILE="/etc/audit/rules.d/60-coolify-baseline.rules"
AUDITD_CONF_FILE="/etc/audit/auditd.conf"
DOCKER_USER_SCRIPT="/usr/local/sbin/docker-user-hardening.sh"
DOCKER_USER_ENV_FILE="/etc/default/docker-user-hardening"
DOCKER_USER_UNIT_FILE="/etc/systemd/system/docker-user-hardening.service"
APT_AUTO_FILE="/etc/apt/apt.conf.d/20auto-upgrades"
APT_LOCAL_FILE="/etc/apt/apt.conf.d/52unattended-upgrades-local"
SYSCTL_DROPIN_FILE="/etc/sysctl.d/99-coolify-hardening.conf"
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
  bootstrap_hardening.sh --admin-user <name> --admin-pubkey "<ssh key>" [options]

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

detect_os() {
  [[ -f /etc/os-release ]] || die "/etc/os-release not found."
  # shellcheck disable=SC1091
  source /etc/os-release
  [[ "${ID:-}" == "ubuntu" ]] || die "Only Ubuntu is supported."
  OS_VERSION="${VERSION_ID:-unknown}"

  if [[ "${OS_VERSION}" != "24.04" ]] && ! is_true "${FORCE}"; then
    die "Expected Ubuntu 24.04.x (found ${OS_VERSION}). Use --force to override."
  fi
}

check_disk_space() {
  local swap_size="${SWAP_SIZE:-2G}"
  local required_mb=512
  if [[ "${swap_size}" != "0" ]]; then
    local swap_num="${swap_size%[GgMm]}"
    local swap_unit="${swap_size: -1}"
    case "${swap_unit,,}" in
      g) required_mb=$(( required_mb + swap_num * 1024 )) ;;
      m) required_mb=$(( required_mb + swap_num )) ;;
    esac
  fi
  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: would check disk space (required: ${required_mb}M)."
    return 0
  fi

  # If a stale swapfile exists and will be removed, we can reclaim that space.
  local swapfile_mb=0
  if [[ -f /swapfile ]] && ! swapon --show --noheadings 2>/dev/null | grep -q '/swapfile'; then
    swapfile_mb="$(du -m /swapfile 2>/dev/null | cut -f1)" || swapfile_mb=0
  fi

  local avail_mb
  avail_mb="$(df -m / 2>/dev/null | awk 'NR==2 {print $4}')"
  if [[ -z "${avail_mb}" || ! "${avail_mb}" =~ ^[0-9]+$ ]]; then
    warn "Cannot determine available disk space; skipping pre-flight check."
    return 0
  fi

  # Add reclaimed swapfile space to available
  local effective_avail=$(( avail_mb + swapfile_mb ))

  if (( effective_avail < required_mb )); then
    die "Insufficient disk space: ${avail_mb}M available (+${swapfile_mb}M from stale swap), ${required_mb}M required (swap: ${swap_size} + 512M base)."
  fi
  log "Disk pre-flight: ${avail_mb}M available, ${required_mb}M required. OK."
}

detect_wan_iface() {
  if [[ -n "${WAN_IFACE}" ]]; then
    return 0
  fi

  WAN_IFACE="$(ip -o route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i+1); exit }}')"
  [[ -n "${WAN_IFACE}" ]] || die "Unable to auto-detect WAN interface. Set --wan-iface."
}

ssh_session_safety_gate() {
  if [[ -z "${SSH_CONNECTION:-}" ]]; then
    return 0
  fi

  local src_ip
  src_ip="${SSH_CONNECTION%% *}"
  if [[ "${src_ip}" != 100.* && "${src_ip}" != fd7a:* ]] && ! is_true "${FORCE}"; then
    die "Current SSH source (${src_ip}) is not Tailscale-like; refusing to continue without --force."
  fi
}

ensure_packages() {
  local packages
  local missing=()
  local fail2ban_missing="false"
  packages=(
    curl
    jq
    gdisk
    ufw
    auditd
    audispd-plugins
    unattended-upgrades
    apt-listchanges
    openssh-server
    iptables
  )

  for pkg in "${packages[@]}"; do
    if ! dpkg-query -W -f='${Status}' "${pkg}" 2>/dev/null | grep -q "install ok installed"; then
      missing+=("${pkg}")
    fi
  done

  if ! dpkg-query -W -f='${Status}' fail2ban 2>/dev/null | grep -q "install ok installed"; then
    fail2ban_missing="true"
  fi

  if ((${#missing[@]} > 0)); then
    log "Installing required packages: ${missing[*]}"
    retry_apt_update
    run_apt_command env DEBIAN_FRONTEND=noninteractive PYTHONWARNINGS=ignore::SyntaxWarning \
      apt-get install -y --no-install-recommends "${missing[@]}"
  fi

  if [[ "${fail2ban_missing}" == "true" ]]; then
    install_fail2ban_without_autostart
  fi
}

install_fail2ban_without_autostart() {
  local policy_rc_d="/usr/sbin/policy-rc.d"
  local policy_backup=""
  local policy_restore="false"
  local install_rc=0

  log "Installing required package: fail2ban (service autostart suppressed until managed config is written)"
  retry_apt_update

  if is_true "${DRY_RUN}"; then
    run_apt_command env DEBIAN_FRONTEND=noninteractive PYTHONWARNINGS=ignore::SyntaxWarning \
      apt-get install -y --no-install-recommends fail2ban
    return 0
  fi

  if [[ -e "${policy_rc_d}" ]]; then
    policy_backup="$(mktemp "${policy_rc_d}.bootstrap-hardening.XXXXXX")"
    cp -a "${policy_rc_d}" "${policy_backup}"
    policy_restore="true"
  fi

  write_file "${policy_rc_d}" "0755" "root" "root" <<'EOF'
#!/usr/bin/env bash
exit 101
EOF

  if ! run_apt_command env DEBIAN_FRONTEND=noninteractive PYTHONWARNINGS=ignore::SyntaxWarning \
    apt-get install -y --no-install-recommends fail2ban; then
    install_rc=$?
  fi

  if [[ "${policy_restore}" == "true" ]]; then
    cp -a "${policy_backup}" "${policy_rc_d}"
    rm -f "${policy_backup}"
  else
    rm -f "${policy_rc_d}"
  fi

  (( install_rc == 0 )) || return "${install_rc}"
}

ensure_system_group() {
  local group_name="$1"
  [[ -n "${group_name}" ]] || die "ensure_system_group requires a non-empty group name."

  if getent group "${group_name}" >/dev/null 2>&1; then
    return 0
  fi

  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: would create missing system group '${group_name}'."
    return 0
  fi

  log "Creating missing system group '${group_name}'."
  run groupadd --system "${group_name}"
}

ensure_power_group() {
  ensure_system_group "power"
}

require_commands() {
  local commands=()
  commands+=(ip awk grep sed jq sgdisk)

  if ! is_true "${DRY_RUN}"; then
    commands+=(sshd ufw iptables journalctl systemctl augenrules auditctl fail2ban-client)
  fi

  for cmd in "${commands[@]}"; do
    command -v "${cmd}" >/dev/null 2>&1 || die "Missing command: ${cmd}"
  done
}

retry_apt_update() {
  local attempts=3 delay=5 i
  for (( i = 1; i <= attempts; i++ )); do
    if run_apt_command apt-get update; then
      return 0
    fi
    if (( i < attempts )); then
      log "apt-get update failed (attempt ${i}/${attempts}); retrying in ${delay}s..."
      sleep "${delay}"
    fi
  done
  die "apt-get update failed after ${attempts} attempts."
}

retry_apt_noninteractive() {
  local description="$1"
  shift

  local attempts=3 delay=10 i
  for (( i = 1; i <= attempts; i++ )); do
    if run_apt_command env DEBIAN_FRONTEND=noninteractive PYTHONWARNINGS=ignore::SyntaxWarning \
      apt-get -y \
      -o Dpkg::Options::=--force-confdef \
      -o Dpkg::Options::=--force-confold \
      "$@"; then
      return 0
    fi
    if (( i < attempts )); then
      log "${description} failed (attempt ${i}/${attempts}); retrying in ${delay}s..."
      sleep "${delay}"
    fi
  done
  die "${description} failed after ${attempts} attempts."
}

emit_filtered_package_output() {
  sed -E \
    -e '/SyntaxWarning: invalid escape sequence/d' \
    -e '/dpkg: warning: while removing .* directory .* not empty so not removed/d' \
    -e '/Service restarts being deferred:/d' \
    -e '/No containers need to be restarted\./d' \
    -e '/No user sessions are running outdated binaries\./d' \
    -e '/No VM guests are running outdated hypervisor.*\./d'
}

run_apt_command() {
  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: $*"
    return 0
  fi

  local tmp rc
  tmp="$(mktemp)"
  if "$@" >"${tmp}" 2>&1; then
    rc=0
  else
    rc=$?
  fi
  emit_filtered_package_output < "${tmp}" || true
  rm -f "${tmp}"
  return "${rc}"
}

ensure_bootloader_embed_safety() {
  # UEFI does not require a BIOS boot partition.
  if [[ -d /sys/firmware/efi ]]; then
    log "UEFI boot detected; BIOS embedding safety check skipped."
    return 0
  fi

  local root_src root_pk disk pttype
  root_src="$(findmnt -n -o SOURCE / 2>/dev/null || true)"
  [[ "${root_src}" =~ ^/dev/ ]] || {
    warn "Unable to determine root block device from '/'; skipping BIOS/GPT bootloader check."
    return 0
  }

  root_pk="$(lsblk -no PKNAME "${root_src}" 2>/dev/null | head -n1 || true)"
  if [[ -z "${root_pk}" ]]; then
    case "${root_src}" in
      /dev/nvme*n[0-9]p[0-9]*) root_pk="${root_src#/dev/}"; root_pk="${root_pk%p*}" ;;
      /dev/*[0-9]) root_pk="${root_src#/dev/}"; root_pk="${root_pk%%[0-9]*}" ;;
      /dev/*) root_pk="${root_src#/dev/}" ;;
    esac
  fi
  [[ -n "${root_pk}" ]] || die "Failed to determine parent disk for root device '${root_src}'."
  disk="/dev/${root_pk}"
  [[ -b "${disk}" ]] || die "Resolved boot disk '${disk}' is not a block device."

  pttype="$(lsblk -dn -o PTTYPE "${disk}" 2>/dev/null | head -n1 | tr -d '[:space:]')"
  if [[ "${pttype}" != "gpt" ]]; then
    log "Boot disk ${disk} partition table is '${pttype:-unknown}'; BIOS/GPT embedding risk not applicable."
    return 0
  fi

  if sgdisk -p "${disk}" | awk '/^[[:space:]]*[0-9]+[[:space:]]+[0-9]+/{ if ($6=="EF02") found=1 } END{ exit(found?0:1) }'; then
    log "BIOS boot partition already present on ${disk} (EF02)."
    return 0
  fi

  log "Detected BIOS boot on GPT without EF02 partition on ${disk}; attempting auto-remediation."

  local first_start end start part_num
  first_start="$(sgdisk -p "${disk}" | awk '/^[[:space:]]*[0-9]+[[:space:]]+[0-9]+/{ print $2; exit }')"
  [[ "${first_start}" =~ ^[0-9]+$ ]] || die "Failed to determine first partition start sector on ${disk}."

  end="$(( first_start - 1 ))"
  start="$(( end - 2047 ))"
  if (( start < 34 )); then
    die "BIOS/GPT bootloader risk: no room to auto-create a 1MiB EF02 partition before ${disk}p1. Rebuild with a BIOS boot partition."
  fi

  part_num="$(sgdisk -p "${disk}" | awk '
    /^[[:space:]]*[0-9]+[[:space:]]+[0-9]+/ { used[$1]=1 }
    END {
      for (i=1; i<=128; i++) {
        if (!(i in used)) {
          print i
          exit
        }
      }
    }'
  )"
  [[ "${part_num}" =~ ^[0-9]+$ ]] || die "No free GPT partition slots available on ${disk}."

  run sgdisk -n "${part_num}:${start}:${end}" -t "${part_num}:ef02" -c "${part_num}:BIOS boot partition" "${disk}"
  run partprobe "${disk}" || true
  run grub-install "${disk}"
  run update-grub

  if sgdisk -p "${disk}" | awk '/^[[:space:]]*[0-9]+[[:space:]]+[0-9]+/{ if ($6=="EF02") found=1 } END{ exit(found?0:1) }'; then
    log "Bootloader embedding safety fixed: created EF02 BIOS boot partition on ${disk} and reinstalled GRUB."
  else
    die "Failed to verify EF02 BIOS boot partition on ${disk} after remediation."
  fi
}

apply_system_package_updates() {
  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: would run apt-get full-upgrade and autoremove for baseline patching."
    return 0
  fi

  retry_apt_update
  log "Applying baseline package patches (apt-get full-upgrade, include phased updates)..."
  retry_apt_noninteractive \
    "apt-get full-upgrade" \
    -o APT::Get::Always-Include-Phased-Updates=true \
    full-upgrade

  log "Removing obsolete packages (apt-get autoremove --purge)..."
  retry_apt_noninteractive "apt-get autoremove --purge" autoremove --purge
  run apt-get -y autoclean

  local upgradable_count
  upgradable_count="$(apt list --upgradable 2>/dev/null | awk 'NR>1{c++} END{print c+0}')"
  if [[ "${upgradable_count}" =~ ^[0-9]+$ && "${upgradable_count}" -eq 0 ]]; then
    log "Baseline patching complete: no upgradable packages remain."
  else
    warn "Baseline patching complete with ${upgradable_count:-unknown} upgradable package(s) still listed."
  fi

  if [[ -f /var/run/reboot-required ]]; then
    warn "System reports reboot required after package updates (/var/run/reboot-required)."
  fi
}

warn_on_state_version_mismatch() {
  [[ -f "${STATE_FILE}" ]] || return 0

  local existing_version
  existing_version="$(grep -m1 '^script_version=' "${STATE_FILE}" | cut -d= -f2- || true)"
  if [[ -n "${existing_version}" && "${existing_version}" != "${SCRIPT_VERSION}" ]]; then
    warn "Existing hardening state found (v${existing_version}), re-running v${SCRIPT_VERSION}."
  fi
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

ensure_timesync() {
  if ! is_true "${DRY_RUN}"; then
    local ntp_active
    ntp_active="$(timedatectl show --property=NTP --value 2>/dev/null || echo "n/a")"
    if [[ "${ntp_active}" != "yes" ]]; then
      if run timedatectl set-ntp true; then
        log "NTP synchronization enabled."
      else
        warn "Could not enable NTP (timedatectl set-ntp failed). Verify manually."
      fi
    else
      log "NTP synchronization already active."
    fi
    local i
    for (( i = 1; i <= 6; i++ )); do
      local synced
      synced="$(timedatectl show --property=NTPSynchronized --value 2>/dev/null || echo "n/a")"
      if [[ "${synced}" == "yes" ]]; then
        log "NTP synchronized."
        return 0
      fi
      log "Waiting for NTP synchronization (${i}/6)..."
      sleep 5
    done
    warn "NTP not synchronized after 30s; continuing. Verify with: timedatectl status"
  else
    log "DRY-RUN: would verify NTP synchronization."
  fi
}

configure_timezone() {
  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: would configure timezone to ${TIMEZONE}."
    return 0
  fi

  if ! command -v timedatectl >/dev/null 2>&1; then
    warn "timedatectl not found; skipping timezone configuration."
    return 0
  fi

  local current_tz
  current_tz="$(timedatectl show --property=Timezone --value 2>/dev/null || true)"
  if [[ "${current_tz}" == "${TIMEZONE}" ]]; then
    log "Timezone already configured: ${TIMEZONE}."
    return 0
  fi

  run timedatectl set-timezone "${TIMEZONE}"
  current_tz="$(timedatectl show --property=Timezone --value 2>/dev/null || true)"
  [[ "${current_tz}" == "${TIMEZONE}" ]] \
    || die "Failed to set timezone to ${TIMEZONE} (current: ${current_tz:-unknown})."
  log "Timezone configured: ${TIMEZONE}."
}

normalize_private_hosts_file() {
  if [[ -z "${DOMAIN}" ]]; then
    log "DOMAIN not provided; skipping /etc/hosts private-domain normalization."
    return 0
  fi

  if [[ ! -f "${HOSTS_FILE}" ]]; then
    warn "${HOSTS_FILE} not found; skipping private-domain normalization."
    return 0
  fi

  local short_host tmp awk_rc
  short_host="$(hostname -s 2>/dev/null || true)"

  if is_true "${DRY_RUN}"; then
    if awk -v dashboard="${DOMAIN}" -v websocket="ws.${DOMAIN}" '
      $0 !~ /^[[:space:]]*#/ && NF > 1 {
        ip=$1
        if (ip ~ /^127\./ || ip == "::1") {
          for (i=2; i<=NF; i++) {
            if ($i == dashboard || $i == websocket) exit 0
          }
        }
      }
      END { exit 1 }
    ' "${HOSTS_FILE}"; then
      log "DRY-RUN: would remove ${DOMAIN} and ws.${DOMAIN} from loopback entries in ${HOSTS_FILE}"
    else
      log "DRY-RUN: ${HOSTS_FILE} already leaves ${DOMAIN} DNS-driven"
    fi
    return 0
  fi

  tmp="$(mktemp)"
  if awk -v dashboard="${DOMAIN}" -v websocket="ws.${DOMAIN}" -v short="${short_host}" '
    function is_loopback(ip) { return ip ~ /^127\./ || ip == "::1" }
    function has_token(arr, count, value,   idx) {
      for (idx = 1; idx <= count; idx++) {
        if (arr[idx] == value) {
          return 1
        }
      }
      return 0
    }
    {
      if ($0 ~ /^[[:space:]]*#/) {
        print
        next
      }
      if (NF == 0) {
        print ""
        next
      }

      ip = $1
      if (!is_loopback(ip)) {
        print
        next
      }

      if (ip == "127.0.1.1") {
        have_12701 = 1
      }

      keep_count = 0
      delete keep
      for (i = 2; i <= NF; i++) {
        token = $i
        if (token == dashboard || token == websocket) {
          changed = 1
          continue
        }
        keep[++keep_count] = token
      }

      if (ip == "127.0.1.1" && short != "" && short != "localhost" && !has_token(keep, keep_count, short)) {
        keep[++keep_count] = short
        changed = 1
      }

      if (keep_count == 0) {
        changed = 1
        next
      }

      printf "%s", ip
      for (i = 1; i <= keep_count; i++) {
        printf " %s", keep[i]
      }
      printf "\n"
    }
    END {
      if (!have_12701 && short != "" && short != "localhost") {
        print "127.0.1.1 " short
        changed = 1
      }
      exit changed ? 10 : 0
    }
  ' "${HOSTS_FILE}" > "${tmp}"; then
    awk_rc=0
  else
    awk_rc=$?
  fi

  case "${awk_rc}" in
    0)
      rm -f "${tmp}"
      log "${HOSTS_FILE} already keeps ${DOMAIN} and ws.${DOMAIN} DNS-driven."
      return 0
      ;;
    10)
      install -m 0644 -o root -g root "${tmp}" "${HOSTS_FILE}"
      rm -f "${tmp}"
      log "Normalized ${HOSTS_FILE} to keep ${DOMAIN} and ws.${DOMAIN} DNS-driven."
      return 0
      ;;
    *)
      rm -f "${tmp}"
      die "Failed to normalize ${HOSTS_FILE} for ${DOMAIN}."
      ;;
  esac
}

configure_swap() {
  local swap_size="${SWAP_SIZE:-2G}"
  [[ "${swap_size}" == "0" ]] && { log "Swap creation disabled (--swap-size 0)."; return 0; }

  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: would configure ${swap_size} swap file at /swapfile."
    return 0
  fi

  if swapon --show --noheadings | grep -q .; then
    log "Swap already active. Skipping."
    return 0
  fi

  local swap_file="/swapfile"
  if [[ -f "${swap_file}" ]]; then
    log "Stale ${swap_file} found (not active in swapon); removing."
    run rm -f "${swap_file}"
  fi
  run fallocate -l "${swap_size}" "${swap_file}"
  run chmod 600 "${swap_file}"
  run mkswap "${swap_file}"
  run swapon "${swap_file}"

  # Accept any existing /swapfile entry to avoid duplicate lines across distro formats.
  if ! grep -qE '^/swapfile[[:space:]]' /etc/fstab; then
    echo "${swap_file} none swap sw 0 0" >> /etc/fstab
  fi

  log "Swap configured: ${swap_size} at ${swap_file}."
}

disable_unused_services() {
  local services=(rpcbind avahi-daemon cups cups-browsed ModemManager udisks2 fwupd upower)
  local unit
  for svc in "${services[@]}"; do
    for unit in "${svc}.service" "${svc}.socket"; do
      if systemctl list-unit-files --no-legend "${unit}" 2>/dev/null | grep -q "${unit}"; then
        log "Disabling and masking ${unit}"
        run systemctl disable --now "${unit}" 2>/dev/null || true
        run systemctl mask "${unit}" 2>/dev/null || true
      fi
    done
  done
}

configure_sysctl() {
  # Migration: remove old 60-prefixed drop-in (replaced by 99- for precedence)
  local old_sysctl="/etc/sysctl.d/60-coolify-hardening.conf"
  if [[ -f "${old_sysctl}" && "${old_sysctl}" != "${SYSCTL_DROPIN_FILE}" ]]; then
    log "Removing superseded sysctl drop-in ${old_sysctl} (replaced by ${SYSCTL_DROPIN_FILE})."
    run rm -f "${old_sysctl}"
  fi

  # Check if BBR kernel module is available
  local bbr_available="false"
  if modinfo tcp_bbr &>/dev/null; then
    bbr_available="true"
  fi

  {
    cat <<'SYSCTL_BASE'
# Managed by bootstrap hardening — Coolify/Docker safe
net.ipv4.ip_forward = 1
net.ipv4.tcp_syncookies = 1
# Redis/Coolify reliability under memory pressure
vm.overcommit_memory = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
# Allow non-root ping sockets so cloudflared ICMP proxy init does not warn.
net.ipv4.ping_group_range = 0 2147483647
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
# SYN flood hardening
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
kernel.unprivileged_bpf_disabled = 2
kernel.kexec_load_disabled = 1
kernel.sysrq = 4
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
kernel.perf_event_paranoid = 3
SYSCTL_BASE

    if [[ "${bbr_available}" == "true" ]]; then
      cat <<'SYSCTL_BBR'
# TCP performance: BBR congestion control
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
SYSCTL_BBR
    fi

    if [[ "${SWAP_SIZE:-2G}" != "0" ]]; then
      cat <<'SYSCTL_SWAP'
# Swap tuning: prefer RAM, use swap only under pressure
vm.swappiness = 10
SYSCTL_SWAP
    fi
  } | write_file "${SYSCTL_DROPIN_FILE}" "0644" "root" "root"

  if [[ "${bbr_available}" == "false" ]]; then
    warn "BBR not available: kernel module tcp_bbr not found. Using default congestion control."
  fi

  run sysctl --system

  if ! is_true "${DRY_RUN}"; then
    local syncookies ip_forward overcommit
    syncookies="$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || echo "?")"
    ip_forward="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "?")"
    overcommit="$(sysctl -n vm.overcommit_memory 2>/dev/null || echo "?")"
    [[ "${syncookies}" == "1" ]] || die "Post-sysctl check failed: tcp_syncookies is ${syncookies}, expected 1."
    [[ "${ip_forward}" == "1" ]] || die "Post-sysctl check failed: ip_forward is ${ip_forward}, expected 1 (Docker requires this)."
    [[ "${overcommit}" == "1" ]] || die "Post-sysctl check failed: vm.overcommit_memory is ${overcommit}, expected 1."

    if [[ "${bbr_available}" == "true" ]]; then
      local bbr
      bbr="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "?")"
      [[ "${bbr}" == "bbr" ]] || warn "BBR not active: ${bbr} (kernel module tcp_bbr may be unavailable)."
    fi
  fi
}

configure_fail2ban() {
  write_file "${FAIL2BAN_LOCAL_FILE}" "0644" "root" "root" <<'EOF'
# Managed by bootstrap hardening
[Definition]
allowipv6 = auto
EOF

  write_file "${FAIL2BAN_JAIL_FILE}" "0644" "root" "root" <<EOF
# Managed by bootstrap hardening
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
banaction = ufw
ignoreip = 127.0.0.1/8 ::1 ${TAILSCALE_CIDR}

[sshd]
enabled = true
port = ${SSH_PORT}
backend = systemd
maxretry = 3
bantime = 1h
EOF

  run systemctl enable --now fail2ban
  if ! is_true "${DRY_RUN}"; then
    run systemctl restart fail2ban
    wait_for_fail2ban_sshd_jail 15 2 \
      || die "fail2ban started but the sshd jail did not become active."
  fi
}

configure_apport() {
  if [[ -f "${APPORT_DEFAULT_FILE}" ]]; then
    if grep -qE '^[[:space:]]*enabled[[:space:]]*=' "${APPORT_DEFAULT_FILE}"; then
      run sed -i -E 's/^[[:space:]]*enabled[[:space:]]*=.*/enabled=0/' "${APPORT_DEFAULT_FILE}"
    else
      if is_true "${DRY_RUN}"; then
        log "DRY-RUN: append 'enabled=0' to ${APPORT_DEFAULT_FILE}"
      else
        printf '\nenabled=0\n' >> "${APPORT_DEFAULT_FILE}"
      fi
    fi
  else
    warn "${APPORT_DEFAULT_FILE} not found; skipping apport defaults update."
  fi

  if unit_available "apport.service"; then
    run systemctl disable --now apport.service
    run systemctl mask apport.service
    log "Apport disabled and masked."
  else
    log "apport.service not installed; skipping."
  fi
}

configure_cron_extra_opts() {
  if ! unit_available "cron.service"; then
    log "cron.service not installed; skipping EXTRA_OPTS normalization."
    return 0
  fi

  write_file "${CRON_EXTRA_OPTS_DROPIN}" "0644" "root" "root" <<'EOF'
[Service]
Environment="EXTRA_OPTS="
EOF

  run systemctl daemon-reload
  run systemctl restart cron
  log "cron.service EXTRA_OPTS environment normalized."
}

configure_networkd_wait_online() {
  if ! unit_available "systemd-networkd-wait-online.service"; then
    log "systemd-networkd-wait-online.service not installed; skipping wait-online tuning."
    return 0
  fi

  write_file "${NETWORKD_WAIT_ONLINE_DROPIN}" "0644" "root" "root" <<'EOF'
[Service]
ExecStart=
ExecStart=/lib/systemd/systemd-networkd-wait-online --any --timeout=15
EOF

  run systemctl daemon-reload

  if ifupdown_is_authoritative; then
    local -a stray_units=()
    unit_available "systemd-networkd.socket" && stray_units+=("systemd-networkd.socket")
    unit_available "systemd-networkd.service" && stray_units+=("systemd-networkd.service")
    unit_available "networkd-dispatcher.service" && stray_units+=("networkd-dispatcher.service")
    if (( ${#stray_units[@]} > 0 )); then
      run systemctl stop "${stray_units[@]}"
      run systemctl disable "${stray_units[@]}"
    fi
    log "ifupdown is authoritative; disabled stray systemd-networkd units to keep apt-helper wait-online on networking.service."
    return 0
  fi

  log "systemd-networkd-wait-online tuned for --any with 15s timeout."
}

configure_banner() {
  write_file "/etc/issue.net" "0644" "root" "root" <<'EOF'
***************************************************************************
                   AUTHORIZED ACCESS ONLY
This system is for authorized use only. All activity may be monitored
and reported. Unauthorized access is prohibited and may be subject to
criminal and civil penalties.
***************************************************************************
EOF
}

ensure_admin_access() {
  local home_dir
  local ssh_dir
  local auth_file
  local user_exists="false"

  if id "${ADMIN_USER}" >/dev/null 2>&1; then
    user_exists="true"
    log "Admin user exists: ${ADMIN_USER}"
  else
    run useradd -m -s /bin/bash -G sudo "${ADMIN_USER}"
  fi

  if [[ "${user_exists}" == "true" ]] && ! id -nG "${ADMIN_USER}" | tr ' ' '\n' | grep -qx "sudo"; then
    run usermod -aG sudo "${ADMIN_USER}"
  fi

  # Configure passwordless sudo for admin user
  # This is required because the admin user has no password set,
  # but sudo requires password by default, blocking all admin operations.
  local sudoers_file="/etc/sudoers.d/${ADMIN_USER}"
  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: would create ${sudoers_file} with passwordless sudo for ${ADMIN_USER}"
  else
    cat > "${sudoers_file}" <<EOF
Defaults:${ADMIN_USER} timestamp_timeout=0
${ADMIN_USER} ALL=(ALL) NOPASSWD: ALL
EOF
    chmod 440 "${sudoers_file}"
    # Validate sudoers syntax before committing
    if ! visudo -c -f "${sudoers_file}" >/dev/null 2>&1; then
      rm -f "${sudoers_file}"
      die "Failed to create valid sudoers file for ${ADMIN_USER}"
    fi
    log "Configured passwordless sudo for ${ADMIN_USER}"
  fi

  if is_true "${DRY_RUN}" && [[ "${user_exists}" == "false" ]]; then
    log "DRY-RUN: would create /home/${ADMIN_USER}/.ssh/authorized_keys with provided key."
    return 0
  fi

  home_dir="$(getent passwd "${ADMIN_USER}" | cut -d: -f6)"
  [[ -n "${home_dir}" ]] || die "Unable to resolve home directory for ${ADMIN_USER}."
  ssh_dir="${home_dir}/.ssh"
  auth_file="${ssh_dir}/authorized_keys"

  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: ensure ${auth_file} contains provided key."
    return 0
  fi

  install -d -m 0700 -o "${ADMIN_USER}" -g "${ADMIN_USER}" "${ssh_dir}"
  touch "${auth_file}"
  chown "${ADMIN_USER}:${ADMIN_USER}" "${auth_file}"
  chmod 0600 "${auth_file}"

  if ! grep -qxF "${ADMIN_PUBKEY}" "${auth_file}"; then
    printf '%s\n' "${ADMIN_PUBKEY}" >> "${auth_file}"
  fi

  # Lock root password — root login is blocked by sshd config but a set
  # password is still a credential that could be leveraged via console or
  # a misconfigured PAM rule.
  if ! is_true "${DRY_RUN}"; then
    local root_pw_status
    root_pw_status="$(passwd -S root 2>/dev/null | awk '{print $2}')"
    if [[ "${root_pw_status}" == "P" ]]; then
      passwd -l root >/dev/null 2>&1
      log "Root password locked."
    fi
  else
    log "DRY-RUN: would lock root password."
  fi

  # Clear root authorized_keys — provisioning systems often inject keys
  # into /root/.ssh/authorized_keys that are unrelated to the admin user.
  # Root login is already blocked from external addresses, but stale keys
  # are a credential that should not persist.
  if ! is_true "${DRY_RUN}"; then
    local root_auth_keys="/root/.ssh/authorized_keys"
    if [[ -f "${root_auth_keys}" ]] && [[ -s "${root_auth_keys}" ]]; then
      : > "${root_auth_keys}"
      log "Cleared root authorized_keys."
    fi
  else
    log "DRY-RUN: would clear root authorized_keys."
  fi
}

restore_ssh_dropin() {
  local backup="$1"
  if is_true "${DRY_RUN}"; then
    return 0
  fi
  if [[ -n "${backup}" && -f "${backup}" ]]; then
    cp -a "${backup}" "${SSH_DROPIN_FILE}"
  else
    rm -f "${SSH_DROPIN_FILE}"
  fi
}

assert_sshd_effective() {
  local effective="$1"

  grep -qE "^port ${SSH_PORT}$" <<< "${effective}" || return 1
  grep -q "^permitrootlogin no$" <<< "${effective}" || return 1
  grep -q "^passwordauthentication no$" <<< "${effective}" || return 1
  grep -q "^kbdinteractiveauthentication no$" <<< "${effective}" || return 1
  grep -q "^pubkeyauthentication yes$" <<< "${effective}" || return 1
  grep -q "^authenticationmethods publickey$" <<< "${effective}" || return 1
  grep -qE "^allowusers .*\\b${ADMIN_USER}\\b" <<< "${effective}" || return 1
  grep -q "^permitemptypasswords no$" <<< "${effective}" || return 1
  grep -q "^compression no$" <<< "${effective}" || return 1
  grep -q "chacha20-poly1305@openssh.com" <<< "${effective}" || return 1
  grep -q "hmac-sha2-512-etm@openssh.com" <<< "${effective}" || return 1
  grep -q "sntrup761x25519-sha512@openssh.com" <<< "${effective}" || return 1
  grep -q "hostkeyalgorithms .*ssh-ed25519" <<< "${effective}" || return 1
}

assert_sshd_match_localhost() {
  local effective="$1"

  # OpenSSH outputs "prohibit-password" or its legacy synonym "without-password"
  grep -qE "^permitrootlogin (prohibit-password|without-password)$" <<< "${effective}" || return 1
  grep -qE "^allowusers .*\\broot\\b" <<< "${effective}" || return 1
  grep -qE "^allowusers .*\\b${ADMIN_USER}\\b" <<< "${effective}" || return 1
}

reload_ssh_service() {
  local units
  local has_ssh="false"
  local has_sshd="false"

  if ! systemctl list-unit-files --type=service --no-legend >/dev/null 2>&1; then
    return 1
  fi

  units="$(systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}')"
  grep -qx "ssh.service" <<< "${units}" && has_ssh="true" || true
  grep -qx "sshd.service" <<< "${units}" && has_sshd="true" || true

  if [[ "${has_ssh}" == "true" ]]; then
    if ! systemctl is-active --quiet ssh; then
      systemctl start ssh || return 1
    fi
    systemctl reload ssh || systemctl restart ssh || return 1
    return 0
  fi

  if [[ "${has_sshd}" == "true" ]]; then
    if ! systemctl is-active --quiet sshd; then
      systemctl start sshd || return 1
    fi
    systemctl reload sshd || systemctl restart sshd || return 1
    return 0
  fi

  return 1
}

unit_available() {
  local unit_name="$1"
  command -v systemctl >/dev/null 2>&1 || return 1
  local load_state
  load_state="$(systemctl show --property=LoadState --value "${unit_name}" 2>/dev/null || true)"
  [[ -n "${load_state}" && "${load_state}" != "not-found" ]]
}

ifupdown_is_authoritative() {
  unit_available "networking.service" || return 1

  local path
  for path in /etc/network/interfaces /etc/network/interfaces.d/*; do
    [[ -f "${path}" ]] || continue
    if awk '
      /^[[:space:]]*#/ { next }
      /^[[:space:]]*iface[[:space:]]+/ {
        if ($2 != "lo") {
          found=1
          exit
        }
      }
      END { exit(found ? 0 : 1) }
    ' "${path}"; then
      return 0
    fi
  done

  return 1
}

add_docker_ssh_cidr() {
  local cidr="$1"
  local existing
  local normalized_cidr

  [[ -n "${cidr}" ]] || return 0
  # SSH/UFW rules here are IPv4-focused.
  [[ "${cidr}" =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/([0-9]|[12][0-9]|3[0-2])$ ]] || return 0

  # Normalize host/prefix form (e.g. 10.0.0.1/24) to canonical network/prefix
  # (10.0.0.0/24) so Match Address and UFW rules remain valid.
  normalized_cidr="$(python3 - "${cidr}" <<'PY'
import ipaddress
import sys
try:
    net = ipaddress.ip_network(sys.argv[1], strict=False)
    if isinstance(net, ipaddress.IPv4Network):
        print(str(net))
except Exception:
    pass
PY
)"
  [[ -n "${normalized_cidr}" ]] || return 0
  cidr="${normalized_cidr}"

  for existing in "${DOCKER_SSH_CIDRS[@]}"; do
    [[ "${existing}" == "${cidr}" ]] && return 0
  done
  DOCKER_SSH_CIDRS+=("${cidr}")
}

discover_docker_ssh_cidrs() {
  local cidr
  DOCKER_SSH_CIDRS=()

  # Discovery source 1: active Docker bridge networks.
  if command -v docker >/dev/null 2>&1; then
    while IFS= read -r cidr; do
      add_docker_ssh_cidr "${cidr}"
    done < <(
      docker network ls --filter driver=bridge -q 2>/dev/null \
        | xargs -r docker network inspect --format '{{range .IPAM.Config}}{{.Subnet}}{{"\n"}}{{end}}' 2>/dev/null \
        | awk 'NF' \
        | sort -u
    )
  fi

  # Discovery source 2: local Docker bridge interfaces.
  # This still works when the Docker daemon is stopped.
  if command -v ip >/dev/null 2>&1; then
    while IFS= read -r cidr; do
      add_docker_ssh_cidr "${cidr}"
    done < <(
      ip -o -4 addr show 2>/dev/null \
        | awk '$2 ~ /^docker0$/ || $2 ~ /^br-[[:alnum:]]+$/ { print $4 }' \
        | awk 'NF' \
        | sort -u
    )
  fi

  if is_true "${STRICT_DOCKER_SSH_CIDRS}"; then
    if [[ ${#DOCKER_SSH_CIDRS[@]} -eq 0 ]]; then
      if [[ "${DOCKER_PRESENT}" == "true" ]]; then
        warn "STRICT_DOCKER_SSH_CIDRS enabled but no Docker bridge CIDRs discovered; falling back to compatibility ranges."
      else
        log "STRICT_DOCKER_SSH_CIDRS enabled while Docker is not installed yet; using compatibility ranges until docker-ssh-cidr-sync discovers bridges."
      fi
      DOCKER_SSH_CIDRS=(10.0.0.0/8 172.16.0.0/12)
    fi
  else
    DOCKER_SSH_CIDRS=(10.0.0.0/8 172.16.0.0/12)
  fi

  log "Docker SSH CIDRs: ${DOCKER_SSH_CIDRS[*]}"
}

configure_ssh() {
  local backup=""
  local effective=""
  local match_addresses="127.0.0.1,::1"
  local cidr

  for cidr in "${DOCKER_SSH_CIDRS[@]}"; do
    match_addresses+=",${cidr}"
  done

  if ! is_true "${DRY_RUN}" && [[ ! -d /run/sshd ]]; then
    install -d -m 0755 /run/sshd
  fi

  if [[ -f "${SSH_DROPIN_FILE}" ]] && ! is_true "${DRY_RUN}"; then
    backup="${SSH_DROPIN_FILE}.bak.$(date +%s)"
    cp -a "${SSH_DROPIN_FILE}" "${backup}"
  fi

  # Fix base sshd_config to not rely solely on drop-in overrides
  local base_config="/etc/ssh/sshd_config"
  if [[ -f "${base_config}" ]] && ! is_true "${DRY_RUN}"; then
    sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' "${base_config}"
    sed -i 's/^X11Forwarding yes/X11Forwarding no/' "${base_config}"
    log "Hardened base sshd_config (PermitRootLogin no, X11Forwarding no)."
  elif [[ -f "${base_config}" ]]; then
    log "DRY-RUN: would harden base sshd_config (PermitRootLogin no, X11Forwarding no)."
  fi

  # Neutralize cloud-init override that re-enables password auth
  local cloud_init_ssh="/etc/ssh/sshd_config.d/50-cloud-init.conf"
  local cloud_init_cfg="/etc/cloud/cloud.cfg.d/99-disable-ssh-password.cfg"
  if ! is_true "${DRY_RUN}"; then
    if [[ -f "${cloud_init_ssh}" ]]; then
      echo "PasswordAuthentication no" > "${cloud_init_ssh}"
      chmod 0644 "${cloud_init_ssh}"
      log "Neutralized ${cloud_init_ssh} (set PasswordAuthentication no)."
    fi
    mkdir -p "$(dirname "${cloud_init_cfg}")"
    echo "ssh_pwauth: false" > "${cloud_init_cfg}"
    log "Prevented cloud-init from re-enabling SSH password auth."
  else
    log "DRY-RUN: would neutralize cloud-init SSH password auth override."
  fi

  write_file "${SSH_DROPIN_FILE}" "0644" "root" "root" <<EOF
# Managed by ${SCRIPT_NAME}
Port ${SSH_PORT}
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
AllowUsers ${ADMIN_USER}
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
Compression no
MaxAuthTries 3
MaxSessions 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
PerSourceMaxStartups 3
# Modern algorithms only — explicit allowlist, no legacy defaults.
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
Banner /etc/issue.net

# Coolify connects to its own host as root via localhost / Docker bridge.
# Compatibility mode uses broad RFC1918 ranges; strict mode uses discovered
# Docker bridge CIDRs with safe fallback if discovery fails.
Match Address ${match_addresses}
    PermitRootLogin prohibit-password
    AllowUsers ${ADMIN_USER} root
EOF

  if is_true "${DRY_RUN}"; then
    return 0
  fi

  if ! sshd -t; then
    restore_ssh_dropin "${backup}"
    die "sshd -t failed after writing SSH hardening drop-in."
  fi

  effective="$(sshd -T 2>/dev/null || true)"
  if ! assert_sshd_effective "${effective}"; then
    restore_ssh_dropin "${backup}"
    die "sshd -T did not match expected hardened values."
  fi

  local match_effective
  match_effective="$(sshd -T -C addr=127.0.0.1,user=root,host=localhost,laddr=127.0.0.1 2>/dev/null || true)"
  if ! assert_sshd_match_localhost "${match_effective}"; then
    restore_ssh_dropin "${backup}"
    die "sshd -T -C (localhost Match block) did not match expected values."
  fi

  if ! reload_ssh_service; then
    restore_ssh_dropin "${backup}"
    die "Failed to reload SSH service."
  fi

  rm -f "${SSH_DROPIN_FILE}".bak.*

  # Remove weak DSA host key — deprecated in OpenSSH 7.0+, not negotiated
  # by our HostKeyAlgorithms list, but the key file should not exist.
  if [[ -f /etc/ssh/ssh_host_dsa_key ]] && ! is_true "${DRY_RUN}"; then
    rm -f /etc/ssh/ssh_host_dsa_key /etc/ssh/ssh_host_dsa_key.pub
    log "Removed deprecated DSA host key."
  elif [[ -f /etc/ssh/ssh_host_dsa_key ]]; then
    log "DRY-RUN: would remove deprecated DSA host key."
  fi
}

configure_ssh_socket() {
  # Bind ssh.socket to Tailscale IP + localhost instead of 0.0.0.0:22.
  # Defense-in-depth: even if UFW is flushed, SSH is not exposed publicly.
  local socket_unit="/etc/systemd/system/ssh.socket"
  local ts_ip=""

  ts_ip="$(tailscale ip -4 2>/dev/null || true)"
  if [[ -z "${ts_ip}" ]]; then
    warn "Could not detect Tailscale IP; skipping ssh.socket binding."
    return 0
  fi

  if ! is_true "${DRY_RUN}"; then
    mkdir -p /etc/systemd/system/ssh.socket.d
    cat > /etc/systemd/system/ssh.socket.d/10-bind-tailscale.conf <<SOCKETEOF
[Socket]
# Override default ListenStream=0.0.0.0:22 — bind to Tailscale + localhost only
ListenStream=
ListenStream=${ts_ip}:22
ListenStream=127.0.0.1:22
ListenStream=[::1]:22
SOCKETEOF
    systemctl daemon-reload
    systemctl restart ssh.socket
    log "Bound ssh.socket to ${ts_ip}:22, 127.0.0.1:22, [::1]:22."
  else
    log "DRY-RUN: would bind ssh.socket to ${ts_ip}:22 and localhost."
  fi
}

configure_password_policy() {
  local pwquality="/etc/security/pwquality.conf"

  if ! is_true "${DRY_RUN}"; then
    cat > "${pwquality}" <<'PWEOF'
# Managed by bootstrap_hardening.sh
minlen = 12
minclass = 3
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
maxrepeat = 3
maxsequence = 4
dictcheck = 1
usercheck = 1
enforcing = 1
retry = 3
PWEOF
    chmod 0644 "${pwquality}"
    log "Applied password quality policy."

    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
    log "Set PASS_MAX_DAYS=90, PASS_MIN_DAYS=1 in login.defs."
  else
    log "DRY-RUN: would apply password quality policy and login.defs."
  fi
}

configure_ufw() {
  local cidr

  # Reconcile managed rules by comment to avoid an all-open fail window from `ufw reset`.
  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: reconcile managed UFW rules (remove stale coolify-hardening-* rules)"
  else
    local ufw_numbered
    local managed_nums=()
    local line rule_num idx
    ufw_numbered="$(ufw status numbered 2>/dev/null || true)"
    while IFS= read -r line; do
      [[ "${line}" == *"coolify-hardening-"* ]] || continue
      rule_num="$(sed -n 's/^\[\([0-9]\+\)\].*/\1/p' <<< "${line}")"
      [[ -n "${rule_num}" ]] && managed_nums+=("${rule_num}")
    done <<< "${ufw_numbered}"
    for (( idx=${#managed_nums[@]}-1; idx>=0; idx-- )); do
      run ufw --force delete "${managed_nums[$idx]}"
    done
  fi

  run ufw default deny incoming
  run ufw default allow outgoing
  run ufw default deny routed

  run ufw allow in on "${TAILSCALE_IFACE}" proto tcp to any port "${SSH_PORT}" comment "coolify-hardening-ssh-tailscale"

  # Allow Coolify to SSH to the host from Docker bridge CIDRs.
  # Compatibility mode uses broad ranges; strict mode uses discovered bridge CIDRs.
  for cidr in "${DOCKER_SSH_CIDRS[@]}"; do
    run ufw allow in proto tcp from "${cidr}" to any port "${SSH_PORT}" comment "coolify-hardening-ssh-docker-bridge"
  done

  # Allow Coolify dashboard, Soketi, and terminal on Tailscale interface only.
  # UFW default deny blocks external access; these rules make them reachable via VPN.
  # 8000 = dashboard, 6001 = Soketi real-time, 6002 = terminal (required since beta.336)
  run ufw allow in on "${TAILSCALE_IFACE}" proto tcp to any port 8000 comment "coolify-hardening-dashboard-tailscale"
  run ufw allow in on "${TAILSCALE_IFACE}" proto tcp to any port 6001 comment "coolify-hardening-soketi-tailscale"
  run ufw allow in on "${TAILSCALE_IFACE}" proto tcp to any port 6002 comment "coolify-hardening-terminal-tailscale"

  if is_true "${TUNNEL_MODE}"; then
    log "Tunnel mode: skipping WAN 80/443 UFW rules (traffic arrives via outbound tunnel)."
  else
    run ufw allow in on "${WAN_IFACE}" proto tcp to any port 80 comment "coolify-hardening-http"
    run ufw allow in on "${WAN_IFACE}" proto tcp to any port 443 comment "coolify-hardening-https"
  fi

  if is_true "${TAILSCALE_DIRECT_WAN}"; then
    run ufw allow in on "${WAN_IFACE}" proto udp to any port 41641 comment "coolify-hardening-tailscale-direct"
  else
    log "Tailscale direct WAN optimization disabled: keeping WAN UDP 41641 closed (DERP fallback only)."
  fi

  # ICMP is allowed via UFW's default before.rules (ufw allow proto icmp is not supported)

  run ufw --force enable
}

rsyslog_collect_log_targets() {
  local cfg
  local -a cfgs=()

  [[ -f /etc/rsyslog.conf ]] && cfgs+=("/etc/rsyslog.conf")
  for cfg in /etc/rsyslog.d/*.conf; do
    [[ -f "${cfg}" ]] || continue
    cfgs+=("${cfg}")
  done

  ((${#cfgs[@]} > 0)) || return 0

  awk '
    /^[[:space:]]*#/ { next }
    {
      for (i = 1; i <= NF; i++) {
        tok = $i
        if (tok ~ /^-?\/var\/log\//) {
          sub(/^-/, "", tok)
          sub(/[;,]+$/, "", tok)
          print tok
        }
      }
    }
  ' "${cfgs[@]}" | sort -u
}

ensure_logrotate_create_directive() {
  local file="$1"
  local log_owner="syslog"
  local log_group="$2"
  if [[ $# -ge 3 ]]; then
    log_owner="$2"
    log_group="$3"
  fi
  local create_line="create 640 ${log_owner} ${log_group}"

  if [[ ! -f "${file}" ]]; then
    warn "Logrotate file ${file} not found; skipping create directive check."
    return 0
  fi

  if grep -Eq "^[[:space:]]*create[[:space:]]+640[[:space:]]+${log_owner}[[:space:]]+${log_group}([[:space:]]|$)" "${file}"; then
    return 0
  fi

  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: add '${create_line}' to ${file}"
    return 0
  fi

  if grep -qE '^[[:space:]]*delaycompress[[:space:]]*$' "${file}"; then
    sed -i "/^[[:space:]]*delaycompress[[:space:]]*$/a\\\t${create_line}" "${file}"
    return 0
  fi

  if grep -qE '^[[:space:]]*compress[[:space:]]*$' "${file}"; then
    sed -i "/^[[:space:]]*compress[[:space:]]*$/a\\\t${create_line}" "${file}"
    return 0
  fi

  if grep -qE '^[[:space:]]*sharedscripts[[:space:]]*$' "${file}"; then
    sed -i "/^[[:space:]]*sharedscripts[[:space:]]*$/i\\\t${create_line}" "${file}"
    return 0
  fi

  sed -i "/^[[:space:]]*}[[:space:]]*$/i\\\t${create_line}" "${file}"
}

configure_rsyslog_targets() {
  local target
  local log_owner="syslog"
  local log_group="adm"

  if ! getent passwd "${log_owner}" >/dev/null 2>&1; then
    warn "User '${log_owner}' not found; using fallback owner root for managed log files."
    log_owner="root"
  fi

  if ! getent group "${log_group}" >/dev/null 2>&1; then
    if getent group syslog >/dev/null 2>&1; then
      log_group="syslog"
    else
      warn "Neither 'adm' nor 'syslog' group found; using fallback group root for managed log files."
      log_group="root"
    fi
  fi

  if getent group syslog >/dev/null 2>&1; then
    if is_true "${DRY_RUN}"; then
      log "DRY-RUN: ensure /var/log is root:syslog mode 0770"
    else
      install -d -m 0770 -o root -g syslog /var/log
    fi
  else
    warn "Group 'syslog' not found; skipping /var/log ownership enforcement."
  fi

  while IFS= read -r target; do
    [[ -n "${target}" ]] || continue
    if is_true "${DRY_RUN}"; then
      log "DRY-RUN: ensure ${target} exists (0640 ${log_owner}:${log_group})"
      continue
    fi
    local target_dir
    target_dir="$(dirname "${target}")"
    if [[ ! -d "${target_dir}" ]]; then
      install -d -m 0755 "${target_dir}"
    fi
    touch "${target}"
    chown "${log_owner}:${log_group}" "${target}"
    chmod 0640 "${target}"
  done < <(rsyslog_collect_log_targets)

  ensure_logrotate_create_directive "/etc/logrotate.d/ufw" "${log_owner}" "${log_group}"
  ensure_logrotate_create_directive "/etc/logrotate.d/rsyslog" "${log_owner}" "${log_group}"

  if unit_available "rsyslog.service"; then
    run systemctl restart rsyslog
  else
    warn "rsyslog.service not found; skipping restart."
  fi
}

install_docker_user_assets() {
  write_file "${DOCKER_USER_SCRIPT}" "0750" "root" "root" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

WAN_IFACE="${WAN_IFACE:-${1:-}}"
TAILSCALE_IFACE="${TAILSCALE_IFACE:-tailscale0}"
TUNNEL_MODE="${TUNNEL_MODE:-false}"

if [[ -z "${WAN_IFACE}" ]]; then
  echo "WAN_IFACE is required." >&2
  exit 1
fi

if ! command -v iptables >/dev/null 2>&1; then
  echo "iptables is required." >&2
  exit 1
fi

is_true() {
  case "${1,,}" in
    1|true|yes|y|on) return 0 ;;
    *) return 1 ;;
  esac
}

ipt() {
  iptables -w "$@"
}

# --- IPv4 ---

ipt -t filter -N DOCKER-USER 2>/dev/null || true
if ! ipt -t filter -C FORWARD -j DOCKER-USER >/dev/null 2>&1; then
  ipt -t filter -I FORWARD 1 -j DOCKER-USER
fi

while true; do
  line_no="$(ipt -t filter -L DOCKER-USER --line-numbers -n | awk '/coolify-hardening-/ { print $1; exit }')"
  [[ -n "${line_no}" ]] || break
  ipt -t filter -D DOCKER-USER "${line_no}" || true
done

ipt -t filter -A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "coolify-hardening-estab" -j RETURN
ipt -t filter -A DOCKER-USER -i "${TAILSCALE_IFACE}" -m comment --comment "coolify-hardening-tailscale" -j ACCEPT
ipt -t filter -A DOCKER-USER -i docker0 -m comment --comment "coolify-hardening-bridge-docker0" -j RETURN
ipt -t filter -A DOCKER-USER -i "br+" -m comment --comment "coolify-hardening-bridge-user" -j RETURN
if ! is_true "${TUNNEL_MODE}"; then
  ipt -t filter -A DOCKER-USER -i "${WAN_IFACE}" -p tcp -m multiport --dports 80,443 -m comment --comment "coolify-hardening-wan-web" -j ACCEPT
fi
ipt -t filter -A DOCKER-USER -i "${WAN_IFACE}" -m comment --comment "coolify-hardening-wan-drop" -j DROP
ipt -t filter -A DOCKER-USER -m comment --comment "coolify-hardening-return" -j RETURN

# --- IPv6 ---

if command -v ip6tables >/dev/null 2>&1; then
  ipt6() {
    ip6tables -w "$@"
  }

  ipt6 -t filter -N DOCKER-USER 2>/dev/null || true
  if ! ipt6 -t filter -C FORWARD -j DOCKER-USER >/dev/null 2>&1; then
    ipt6 -t filter -I FORWARD 1 -j DOCKER-USER
  fi

  while true; do
    line_no="$(ipt6 -t filter -L DOCKER-USER --line-numbers -n | awk '/coolify-hardening-/ { print $1; exit }')"
    [[ -n "${line_no}" ]] || break
    ipt6 -t filter -D DOCKER-USER "${line_no}" || true
  done

  ipt6 -t filter -A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "coolify-hardening-estab6" -j RETURN
  ipt6 -t filter -A DOCKER-USER -i "${TAILSCALE_IFACE}" -m comment --comment "coolify-hardening-tailscale6" -j ACCEPT
  ipt6 -t filter -A DOCKER-USER -i docker0 -m comment --comment "coolify-hardening-bridge-docker06" -j RETURN
  ipt6 -t filter -A DOCKER-USER -i "br+" -m comment --comment "coolify-hardening-bridge-user6" -j RETURN
  if ! is_true "${TUNNEL_MODE}"; then
    ipt6 -t filter -A DOCKER-USER -i "${WAN_IFACE}" -p tcp -m multiport --dports 80,443 -m comment --comment "coolify-hardening-wan-web6" -j ACCEPT
  fi
  ipt6 -t filter -A DOCKER-USER -i "${WAN_IFACE}" -m comment --comment "coolify-hardening-wan-drop6" -j DROP
  ipt6 -t filter -A DOCKER-USER -m comment --comment "coolify-hardening-return6" -j RETURN
else
  echo "ip6tables not available; skipping IPv6 DOCKER-USER rules." >&2
fi
EOF

  write_file "${DOCKER_USER_ENV_FILE}" "0644" "root" "root" <<EOF
WAN_IFACE=${WAN_IFACE}
TAILSCALE_IFACE=${TAILSCALE_IFACE}
TUNNEL_MODE=${TUNNEL_MODE}
EOF

  write_file "${DOCKER_USER_UNIT_FILE}" "0644" "root" "root" <<EOF
[Unit]
Description=Apply managed DOCKER-USER hardening rules
After=docker.service
Requires=docker.service
PartOf=docker.service

[Service]
Type=oneshot
EnvironmentFile=${DOCKER_USER_ENV_FILE}
ExecStart=${DOCKER_USER_SCRIPT}
RemainAfterExit=yes

[Install]
WantedBy=docker.service
EOF
}

detect_docker() {
  if command -v docker >/dev/null 2>&1; then
    DOCKER_PRESENT="true"
    log "Docker detected."

    # Docker nftables backend makes DOCKER-USER iptables enforcement ineffective.
    local docker_info
    docker_info="$(docker info 2>/dev/null || true)"
    if [[ -n "${docker_info}" ]] && grep -qiE 'iptables:\s*false|firewall:\s*nftables' <<< "${docker_info}"; then
      die "Docker nftables backend detected; DOCKER-USER iptables hardening is unsupported. Reconfigure Docker to iptables backend before continuing."
    fi
  else
    log "Docker not detected."
  fi
}

docker_daemon_ready() {
  systemctl is-active --quiet docker.service 2>/dev/null || return 1
  docker info >/dev/null 2>&1
}

wait_for_systemd_unit_success() {
  local unit_name="$1"
  local attempts="${2:-15}"
  local delay="${3:-2}"
  local attempt active_state result

  for (( attempt=1; attempt<=attempts; attempt++ )); do
    if systemctl is-active --quiet "${unit_name}" 2>/dev/null; then
      return 0
    fi

    active_state="$(systemctl show "${unit_name}" --property=ActiveState --value 2>/dev/null || true)"
    result="$(systemctl show "${unit_name}" --property=Result --value 2>/dev/null || true)"
    if [[ "${active_state}" == "inactive" && "${result}" == "success" ]]; then
      return 0
    fi

    (( attempt < attempts )) || break
    sleep "${delay}"
  done

  return 1
}

wait_for_docker_daemon_ready() {
  local attempts="${1:-20}"
  local delay="${2:-2}"
  local attempt

  [[ "${DOCKER_PRESENT}" == "true" ]] || return 0
  for (( attempt=1; attempt<=attempts; attempt++ )); do
    if docker_daemon_ready; then
      return 0
    fi
    (( attempt < attempts )) || break
    sleep "${delay}"
  done

  return 1
}

docker_user_rules_present() {
  iptables -S DOCKER-USER 2>/dev/null | grep -q "coolify-hardening"
}

ensure_docker_user_service_applied() {
  local context="${1:-docker-user-hardening}"

  if [[ "${DOCKER_PRESENT}" != "true" ]]; then
    return 0
  fi

  wait_for_docker_daemon_ready 20 2 \
    || die "${context}: Docker daemon did not become ready."
  run systemctl start docker-user-hardening.service
  if is_true "${DRY_RUN}"; then
    return 0
  fi

  wait_for_systemd_unit_success "docker-user-hardening.service" 15 2 \
    || die "${context}: docker-user-hardening.service did not complete successfully."
  docker_user_rules_present \
    || die "${context}: DOCKER-USER rules were not applied."
  DOCKER_RULES_APPLIED="true"
}

wait_for_fail2ban_sshd_jail() {
  local attempts="${1:-15}"
  local delay="${2:-2}"
  local attempt

  if is_true "${DRY_RUN}"; then
    return 0
  fi

  for (( attempt=1; attempt<=attempts; attempt++ )); do
    if systemctl is-active --quiet fail2ban 2>/dev/null \
      && fail2ban-client status sshd >/dev/null 2>&1; then
      return 0
    fi
    (( attempt < attempts )) || break
    sleep "${delay}"
  done

  return 1
}

configure_docker_user() {
  install_docker_user_assets

  # Remove stale WantedBy=multi-user.target symlinks from prior script versions
  if ! is_true "${DRY_RUN}"; then
    systemctl disable docker-user-hardening.service 2>/dev/null || true
  fi
  run systemctl daemon-reload
  local docker_service_present="false"
  if unit_available "docker.service"; then
    docker_service_present="true"
    run systemctl enable docker-user-hardening.service
  else
    log "docker.service not found yet; deferring docker-user-hardening enable until Docker is installed."
  fi

  if [[ "${DOCKER_PRESENT}" == "true" ]]; then
    # Docker CLI may exist while docker.service is not yet installed/available.
    if [[ "${docker_service_present}" == "true" ]]; then
      ensure_docker_user_service_applied "Docker hardening"
    else
      warn "Docker CLI detected but docker.service is not present; DOCKER-USER enable/start deferred."
    fi
  else
    log "Docker not detected; DOCKER-USER unit installed with deferred enable/start until Docker is installed."
  fi
}

DOCKER_DAEMON_JSON="/etc/docker/daemon.json"

configure_docker_daemon() {
  # Required settings for hardening
  # Note: log-driver uses json-file (same as Coolify) for compatibility.
  # Hardening owns: log-driver, log-opts, live-restore, default-ipc-mode,
  #   storage-driver, default-ulimits. Coolify may add: default-address-pools.
  #
  # Intentionally NOT added (verified against 344 Coolify service templates):
  #   no-new-privileges  — breaks Glances, Home Assistant, Forgejo DinD
  #   userns-remap       — breaks volume ownership + Docker socket mounting
  #   icc: false          — breaks inter-container networking (app→PostgreSQL→Redis)
  #   userland-proxy: false — risky for user service deployments
  local required_settings
  required_settings="$(jq -nc \
    --argjson nproc_hard "${DOCKER_NPROC_HARD}" \
    --argjson nproc_soft "${DOCKER_NPROC_SOFT}" \
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
    }')"

  if [[ "${DOCKER_PRESENT}" != "true" ]]; then
    log "Docker not present; skipping daemon.json creation (will be needed post-install)."
    return 0
  fi

  if [[ -f "${DOCKER_DAEMON_JSON}" ]]; then
    # File exists - merge our required settings with existing config
    log "Merging hardening settings into existing ${DOCKER_DAEMON_JSON}"

    if is_true "${DRY_RUN}"; then
      log "DRY-RUN: would merge hardening settings into ${DOCKER_DAEMON_JSON}"
      return 0
    fi

    # Check if jq is available for proper JSON merging
    if ! command -v jq >/dev/null 2>&1; then
      warn "jq not installed; installing for JSON merge..."
      retry_apt_update
      run env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends jq
    fi

    # Backup existing config
    local backup="${DOCKER_DAEMON_JSON}.bak.$(date +%s)"
    cp -a "${DOCKER_DAEMON_JSON}" "${backup}"
    log "Backed up ${DOCKER_DAEMON_JSON} to ${backup}"

    # Merge: our settings take precedence but preserve other existing settings
    local merged required_tmp
    required_tmp="$(mktemp)"
    echo "${required_settings}" > "${required_tmp}"
    merged="$(jq -s '.[0] * .[1]' "${DOCKER_DAEMON_JSON}" "${required_tmp}" 2>/dev/null)"
    rm -f "${required_tmp}"

    if [[ -z "${merged}" ]]; then
      die "Failed to merge ${DOCKER_DAEMON_JSON} with jq; cannot safely apply hardening settings."
    else
      echo "${merged}" > "${DOCKER_DAEMON_JSON}"
      chmod 0644 "${DOCKER_DAEMON_JSON}"
    fi

    if systemctl is-active --quiet docker; then
      DOCKER_DAEMON_NEEDS_RESTART="true"
      log "Docker daemon.json updated; restart deferred until after DOCKER-USER rules are applied."
    else
      rm -f "${DOCKER_DAEMON_JSON}".bak.*
    fi

    log "Docker daemon.json updated with hardening settings."
    return 0
  fi

  # File doesn't exist - create it
  # Note: log-driver uses json-file (same as Coolify) for compatibility.
  # Hardening owns: log-driver, log-opts, live-restore, default-ipc-mode,
  #   storage-driver, default-ulimits. Coolify may add: default-address-pools.
  write_file "${DOCKER_DAEMON_JSON}" "0644" "root" "root" <<EOF
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "live-restore": true,
  "default-ipc-mode": "private",
  "storage-driver": "overlay2",
  "default-ulimits": {
    "nofile": { "Name": "nofile", "Hard": 65536, "Soft": 65536 },
    "nproc": { "Name": "nproc", "Hard": ${DOCKER_NPROC_HARD}, "Soft": ${DOCKER_NPROC_SOFT} }
  }
}
EOF

  log "Docker daemon.json written with log rotation, live-restore, IPC isolation, overlay2, and ulimits."
}

configure_journald() {
  write_file "${JOURNALD_DROPIN_FILE}" "0644" "root" "root" <<EOF
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=${JOURNAL_MAX_USE}
SystemKeepFree=500M
MaxRetentionSec=${JOURNAL_RETENTION}
EOF
  run journalctl --flush
  run systemctl restart systemd-journald

  # Verify persistent storage is active (journald should create /var/log/journal)
  if ! is_true "${DRY_RUN}"; then
    local flush_check=0
    local max_wait=10
    while (( flush_check < max_wait )); do
      if [[ -d /var/log/journal ]]; then
        log "Journald persistent storage verified (/var/log/journal exists)."
        break
      fi
      sleep 1
      ((++flush_check))
    done
    if (( flush_check >= max_wait )) && [[ ! -d /var/log/journal ]]; then
      warn "Journald persistent storage directory /var/log/journal not found after ${max_wait}s. Verify with: journalctl --verify"
    fi
  fi
}

build_audit_rules() {
  # Modern syscall-form rules — higher performance than legacy -w syntax.
  # File watches use: -a always,exit -F path=... -F perm=wa
  # Dir  watches use: -a always,exit -F dir=...  -F perm=wa
  # Exec watches use: -a always,exit -F path=... -F perm=x
  cat <<'EOF'
# Managed by bootstrap hardening (syscall-form)
# Identity files
-a always,exit -F path=/etc/passwd -F perm=wa -k identity
-a always,exit -F path=/etc/shadow -F perm=wa -k identity
-a always,exit -F path=/etc/group -F perm=wa -k identity
-a always,exit -F path=/etc/gshadow -F perm=wa -k identity
# SSH config
-a always,exit -F path=/etc/ssh/sshd_config -F perm=wa -k sshd-config
-a always,exit -F dir=/etc/ssh/sshd_config.d -F perm=wa -k sshd-config
# Time
-a always,exit -F path=/etc/localtime -F perm=wa -k time-change
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change
# Network / locale
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
# Sudoers
-a always,exit -F path=/etc/sudoers -F perm=wa -k sudoers-change
-a always,exit -F dir=/etc/sudoers.d -F perm=wa -k sudoers-change
# Kernel module loading (important for container hosts)
-a always,exit -F path=/etc/modules -F perm=wa -k kernel-module
-a always,exit -F dir=/etc/modprobe.d -F perm=wa -k kernel-module
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -F auid>=1000 -F auid!=unset -k kernel-module
-a always,exit -F arch=b32 -S init_module,finit_module,delete_module -F auid>=1000 -F auid!=unset -k kernel-module
# User command tracking — forensic attribution via auid
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=unset -k user_commands
-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=unset -k user_commands
EOF

  local bin
  for bin in /usr/bin/docker /usr/bin/dockerd /usr/bin/containerd; do
    if [[ -e "${bin}" ]]; then
      printf -- "-a always,exit -F path=%s -F perm=x -k container-runtime\n" "${bin}"
    fi
  done

  local path
  for path in /var/run/docker.sock /etc/docker/; do
    if [[ -e "${path}" ]]; then
      if [[ -d "${path}" ]]; then
        printf -- "-a always,exit -F dir=%s -F perm=wa -k docker-config\n" "${path%/}"
      else
        printf -- "-a always,exit -F path=%s -F perm=wa -k docker-config\n" "${path}"
      fi
    fi
  done
}

set_auditd_conf_kv() {
  local key="$1"
  local value="$2"

  [[ -f "${AUDITD_CONF_FILE}" ]] || return 0

  if grep -qE "^[[:space:]]*${key}[[:space:]]*=" "${AUDITD_CONF_FILE}"; then
    run sed -i -E "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${value}|" "${AUDITD_CONF_FILE}"
  else
    if is_true "${DRY_RUN}"; then
      log "DRY-RUN: append '${key} = ${value}' to ${AUDITD_CONF_FILE}"
    else
      printf '%s = %s\n' "${key}" "${value}" >> "${AUDITD_CONF_FILE}"
    fi
  fi
}

configure_auditd_policy() {
  if [[ ! -f "${AUDITD_CONF_FILE}" ]]; then
    warn "${AUDITD_CONF_FILE} not found; skipping auditd failure-policy tuning."
    return 0
  fi

  # Preserve historical logs and avoid silent overwrite; pair with space thresholds.
  set_auditd_conf_kv "max_log_file_action" "keep_logs"
  set_auditd_conf_kv "space_left" "100"
  set_auditd_conf_kv "space_left_action" "syslog"
  set_auditd_conf_kv "admin_space_left" "50"
  set_auditd_conf_kv "admin_space_left_action" "suspend"
  set_auditd_conf_kv "disk_full_action" "suspend"
  set_auditd_conf_kv "disk_error_action" "suspend"
}

configure_auditd() {
  local tmp
  tmp="$(mktemp)"
  build_audit_rules > "${tmp}"

  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: write ${AUDIT_RULES_FILE}"
    rm -f "${tmp}"
  else
    install -d -m 0755 "$(dirname "${AUDIT_RULES_FILE}")"
    install -m 0640 -o root -g root "${tmp}" "${AUDIT_RULES_FILE}"
    rm -f "${tmp}"
  fi

  run systemctl enable --now auditd || warn "auditd could not be started (container/kernel limitation); rules file written."
  run augenrules --load
  configure_auditd_policy
  run systemctl restart auditd || warn "auditd restart failed after auditd.conf policy update."
}

configure_unattended_upgrades() {
  local reboot_bool
  reboot_bool="false"
  if is_true "${ENABLE_AUTO_REBOOT}"; then
    reboot_bool="true"
  fi

  log "Configuring unattended-upgrades profile: ${UPDATE_PROFILE}"

  write_file "${APT_AUTO_FILE}" "0644" "root" "root" <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

  write_file "${APT_LOCAL_FILE}" "0644" "root" "root" <<EOF
Unattended-Upgrade::Origins-Pattern {
$(case "${UPDATE_PROFILE}" in
  security-only)
    cat <<'PROFILEEOF'
    "origin=Ubuntu,codename=${distro_codename}-security,label=Ubuntu";
PROFILEEOF
    ;;
  balanced)
    cat <<'PROFILEEOF'
    "origin=Ubuntu,codename=${distro_codename}-security,label=Ubuntu";
    "origin=Ubuntu,codename=${distro_codename}-updates,label=Ubuntu";
    "origin=Docker,label=Docker CE,archive=${distro_codename},component=stable";
PROFILEEOF
    ;;
esac)
};
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Automatic-Reboot "${reboot_bool}";
Unattended-Upgrade::Automatic-Reboot-Time "${AUTO_REBOOT_TIME}";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
$(if [[ -n "${UPGRADE_MAIL}" ]]; then
  printf 'Unattended-Upgrade::Mail "%s";\n' "${UPGRADE_MAIL}"
  printf 'Unattended-Upgrade::MailReport "only-on-error";\n'
fi)
EOF

  run systemctl enable --now apt-daily.timer apt-daily-upgrade.timer

  # Set Persistent=false to prevent boot-time catch-up blocking other package operations
  # See: https://documentation.ubuntu.com/server/how-to/software/automatic-updates/
  if ! is_true "${DRY_RUN}"; then
    mkdir -p /etc/systemd/system/apt-daily.timer.d
    cat > /etc/systemd/system/apt-daily.timer.d/override.conf <<'EOF'
[Timer]
Persistent=false
EOF
    mkdir -p /etc/systemd/system/apt-daily-upgrade.timer.d
    cat > /etc/systemd/system/apt-daily-upgrade.timer.d/override.conf <<'EOF'
[Timer]
Persistent=false
EOF
    systemctl daemon-reload
    log "Configured apt timers with Persistent=false to prevent boot-time catch-up."
  else
    log "DRY-RUN: would configure apt timers with Persistent=false"
  fi

  if ! is_true "${DRY_RUN}"; then
    unattended-upgrade --dry-run --debug >/tmp/unattended-upgrade-dryrun.log 2>&1 || warn "unattended-upgrade dry-run returned non-zero; see /tmp/unattended-upgrade-dryrun.log"
  fi
}

bool_cmd() {
  if "$@" >/dev/null 2>&1; then
    echo "true"
  else
    echo "false"
  fi
}

is_container_runtime() {
  if [[ -f /.dockerenv || "${container:-}" == "docker" ]]; then
    return 0
  fi
  if command -v systemd-detect-virt >/dev/null 2>&1 && systemd-detect-virt -cq; then
    return 0
  fi
  return 1
}

assert_rsyslog_posture() {
  local log_dir_owner log_dir_group log_dir_mode log_dir_group_digit
  local target q_target target_owner target_group target_mode
  local expected_dir_group="syslog"
  local expected_target_owner="syslog"
  local expected_target_group="adm"
  local require_dir_group_write="true"

  if ! getent group syslog >/dev/null 2>&1; then
    expected_dir_group="root"
    require_dir_group_write="false"
  fi
  if ! getent passwd syslog >/dev/null 2>&1; then
    expected_target_owner="root"
  fi
  if ! getent group "${expected_target_group}" >/dev/null 2>&1; then
    if getent group syslog >/dev/null 2>&1; then
      expected_target_group="syslog"
    else
      expected_target_group="root"
    fi
  fi

  log_dir_owner="$(stat -c '%U' /var/log 2>/dev/null || true)"
  log_dir_group="$(stat -c '%G' /var/log 2>/dev/null || true)"
  log_dir_mode="$(stat -c '%a' /var/log 2>/dev/null || true)"
  [[ "${log_dir_owner}" == "root" ]] || die "Post-check failed: /var/log owner is ${log_dir_owner:-unknown}, expected root."
  [[ "${log_dir_group}" == "${expected_dir_group}" ]] || die "Post-check failed: /var/log group is ${log_dir_group:-unknown}, expected ${expected_dir_group}."
  [[ "${log_dir_mode}" =~ ^[0-7]{3,4}$ ]] || die "Post-check failed: /var/log mode unreadable (${log_dir_mode:-unknown})."
  if is_true "${require_dir_group_write}"; then
    log_dir_group_digit="${log_dir_mode: -2:1}"
    if (( (10#${log_dir_group_digit} & 2) == 0 )); then
      die "Post-check failed: /var/log mode ${log_dir_mode} lacks group write; rsyslog cannot create missing log targets."
    fi
  fi

  while IFS= read -r target; do
    [[ -n "${target}" ]] || continue
    [[ -f "${target}" ]] || die "Post-check failed: rsyslog target ${target} is missing."
    target_owner="$(stat -c '%U' "${target}" 2>/dev/null || true)"
    target_group="$(stat -c '%G' "${target}" 2>/dev/null || true)"
    target_mode="$(stat -c '%a' "${target}" 2>/dev/null || true)"
    [[ "${target_owner}" == "${expected_target_owner}" ]] || die "Post-check failed: ${target} owner is ${target_owner:-unknown}, expected ${expected_target_owner}."
    [[ "${target_group}" == "${expected_target_group}" ]] || die "Post-check failed: ${target} group is ${target_group:-unknown}, expected ${expected_target_group}."
    [[ "${target_mode}" == "640" ]] || die "Post-check failed: ${target} mode is ${target_mode:-unknown}, expected 640."
    printf -v q_target '%q' "${target}"
    if getent passwd syslog >/dev/null 2>&1; then
      su -s /bin/sh -c "test -w ${q_target}" syslog \
        || die "Post-check failed: rsyslog user cannot write ${target}."
    fi
  done < <(rsyslog_collect_log_targets)

  if [[ -f /etc/logrotate.d/ufw ]]; then
    grep -Eq "^[[:space:]]*create[[:space:]]+640[[:space:]]+${expected_target_owner}[[:space:]]+${expected_target_group}([[:space:]]|$)" /etc/logrotate.d/ufw \
      || die "Post-check failed: /etc/logrotate.d/ufw missing create 640 ${expected_target_owner} ${expected_target_group} directive."
  else
    warn "Post-check: /etc/logrotate.d/ufw not found; skipping create directive assertion."
  fi
  if [[ -f /etc/logrotate.d/rsyslog ]]; then
    grep -Eq "^[[:space:]]*create[[:space:]]+640[[:space:]]+${expected_target_owner}[[:space:]]+${expected_target_group}([[:space:]]|$)" /etc/logrotate.d/rsyslog \
      || die "Post-check failed: /etc/logrotate.d/rsyslog missing create 640 ${expected_target_owner} ${expected_target_group} directive."
  else
    warn "Post-check: /etc/logrotate.d/rsyslog not found; skipping create directive assertion."
  fi
}

run_post_checks() {
  if is_true "${DRY_RUN}"; then
    log "Dry-run complete; post-apply checks skipped."
    return 0
  fi

  local ssh_effective
  ssh_effective="$(sshd -T 2>/dev/null || true)"
  assert_sshd_effective "${ssh_effective}" || die "Post-check failed: sshd effective settings do not match expected hardening."

  local ssh_match_local
  ssh_match_local="$(sshd -T -C addr=127.0.0.1,user=root,host=localhost,laddr=127.0.0.1 2>/dev/null || true)"
  assert_sshd_match_localhost "${ssh_match_local}" || die "Post-check failed: SSH Match block for localhost/Docker root access not effective."

  local ssh_match_external
  ssh_match_external="$(sshd -T -C addr=203.0.113.1,user=root,host=example.com,laddr=0.0.0.0 2>/dev/null || true)"
  if grep -qE "^permitrootlogin (prohibit-password|without-password|yes)$" <<< "${ssh_match_external}"; then
    die "Post-check failed: root login permitted from external address (Match block leak)."
  fi

  ufw status | grep -q "^Status: active$" || die "Post-check failed: UFW is not active."
  ufw status verbose | grep -qE "${SSH_PORT}/tcp.*on ${TAILSCALE_IFACE}.*ALLOW IN" || die "Post-check failed: SSH allow rule on ${TAILSCALE_IFACE} missing."
  if ufw status verbose | grep -qE "${SSH_PORT}/tcp.*on ${WAN_IFACE}.*ALLOW IN"; then
    die "Post-check failed: SSH appears allowed on WAN interface ${WAN_IFACE}."
  fi

  if is_true "${TUNNEL_MODE}"; then
    if ufw status verbose | grep -qE "80/tcp.*on ${WAN_IFACE}.*ALLOW IN"; then
      die "Post-check failed: tunnel-mode is active but WAN port 80 UFW rule exists."
    fi
    if ufw status verbose | grep -qE "443/tcp.*on ${WAN_IFACE}.*ALLOW IN"; then
      die "Post-check failed: tunnel-mode is active but WAN port 443 UFW rule exists."
    fi
  fi

  if is_true "${TAILSCALE_DIRECT_WAN}"; then
    if ! ufw status verbose | grep -qE "41641/udp.*on ${WAN_IFACE}.*ALLOW IN"; then
      die "Post-check failed: TAILSCALE_DIRECT_WAN=true but WAN UDP 41641 UFW rule is missing."
    fi
  else
    if ufw status verbose | grep -qE "41641/udp.*on ${WAN_IFACE}.*ALLOW IN"; then
      die "Post-check failed: TAILSCALE_DIRECT_WAN=false but WAN UDP 41641 UFW rule exists."
    fi
  fi

  if [[ "${DOCKER_PRESENT}" == "true" ]]; then
    local docker_service_present="false"
    if unit_available "docker.service"; then
      docker_service_present="true"
    fi

    if [[ "${DOCKER_RULES_APPLIED}" == "true" ]]; then
      iptables -t filter -S DOCKER-USER | grep -q "coolify-hardening-wan-drop" || die "Post-check failed: DOCKER-USER IPv4 drop rule missing."
      iptables -t filter -S DOCKER-USER | grep -q "coolify-hardening-bridge-docker0" || die "Post-check failed: DOCKER-USER bridge-docker0 rule missing."
      if is_true "${TUNNEL_MODE}"; then
        if iptables -t filter -S DOCKER-USER | grep -q "coolify-hardening-wan-web"; then
          die "Post-check failed: tunnel-mode is active but DOCKER-USER wan-web ACCEPT rule exists."
        fi
      fi
      if command -v ip6tables >/dev/null 2>&1; then
        ip6tables -t filter -S DOCKER-USER 2>/dev/null | grep -q "coolify-hardening-wan-drop6" || die "Post-check failed: DOCKER-USER IPv6 drop rule missing."
      fi
    elif [[ "${docker_service_present}" == "true" ]]; then
      die "Post-check failed: docker.service exists but DOCKER-USER rules were not applied."
    else
      warn "Post-check: Docker CLI is present but docker.service is unavailable; skipping DOCKER-USER chain assertions."
    fi

    if [[ -S /var/run/docker.sock ]]; then
      local docker_sock_mode docker_sock_other docker_sock_owner_group
      docker_sock_mode="$(stat -c '%a' /var/run/docker.sock 2>/dev/null || true)"
      docker_sock_owner_group="$(stat -c '%U:%G' /var/run/docker.sock 2>/dev/null || true)"

      if [[ -n "${docker_sock_mode}" ]]; then
        docker_sock_other="${docker_sock_mode: -1}"
        if [[ "${docker_sock_other}" =~ ^[0-7]$ ]] && (( (10#${docker_sock_other} & 2) != 0 )); then
          die "Post-check failed: /var/run/docker.sock is world-writable (mode ${docker_sock_mode})."
        fi
      fi

      if [[ -n "${docker_sock_owner_group}" && ! "${docker_sock_owner_group}" =~ ^root: ]]; then
        warn "Post-check: /var/run/docker.sock owner/group is ${docker_sock_owner_group}; expected root:*."
      fi
    else
      warn "Post-check: /var/run/docker.sock missing; cannot validate Docker socket permissions."
    fi

    if getent group docker >/dev/null 2>&1; then
      local docker_group_members
      docker_group_members="$(getent group docker | awk -F: '{print $4}')"
      if [[ -n "${docker_group_members}" ]]; then
        warn "Post-check: docker group has named members (${docker_group_members}); Docker access is root-equivalent."
      fi
      if id -nG "${ADMIN_USER}" 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
        warn "Post-check: admin user ${ADMIN_USER} is in docker group (root-equivalent Docker access)."
      fi
    fi
  fi

  if [[ "${DOCKER_PRESENT}" == "true" && -f "${DOCKER_DAEMON_JSON}" ]]; then
    grep -q '"log-driver"' "${DOCKER_DAEMON_JSON}" || warn "Post-check: Docker daemon.json exists but log-driver not configured."
    grep -q '"live-restore"' "${DOCKER_DAEMON_JSON}" || warn "Post-check: Docker daemon.json exists but live-restore not configured."
    grep -q '"default-ipc-mode"' "${DOCKER_DAEMON_JSON}" || warn "Post-check: Docker daemon.json exists but default-ipc-mode not configured."
    grep -q '"storage-driver"' "${DOCKER_DAEMON_JSON}" || warn "Post-check: Docker daemon.json exists but storage-driver not configured."
    grep -q '"default-ulimits"' "${DOCKER_DAEMON_JSON}" || warn "Post-check: Docker daemon.json exists but default-ulimits not configured."
  fi

  if is_true "${STRICT_DOCKER_SSH_CIDRS}"; then
    if ! systemctl is-active --quiet docker-ssh-cidr-sync.timer 2>/dev/null; then
      warn "Post-check: docker-ssh-cidr-sync.timer is not active; Docker CIDR drift auto-reconcile is disabled."
    fi
  fi

  grep -q "^Storage=persistent$" "${JOURNALD_DROPIN_FILE}" || die "Post-check failed: journald persistence drop-in missing."

  local audit_rules_blob=""
  local audit_rules_source="live"
  if command -v auditctl >/dev/null 2>&1; then
    audit_rules_blob="$(auditctl -l 2>/dev/null || true)"
  fi
  if [[ -z "${audit_rules_blob}" ]]; then
    audit_rules_blob="$(cat "${AUDIT_RULES_FILE}" 2>/dev/null || true)"
    audit_rules_source="file"
  fi

  if ! systemctl is-active --quiet auditd 2>/dev/null; then
    if is_container_runtime; then
      warn "Post-check: auditd inactive in container; validating persisted audit rules file."
    else
      die "Post-check failed: auditd is not active."
    fi
  elif [[ "${audit_rules_source}" != "live" ]]; then
    die "Post-check failed: could not read live audit rules from auditctl."
  fi

  grep -q "identity" <<< "${audit_rules_blob}" \
    || die "Post-check failed: audit identity rules missing."
  grep -q "sudoers-change" <<< "${audit_rules_blob}" \
    || die "Post-check failed: sudoers audit rules missing."
  grep -q "user_commands" <<< "${audit_rules_blob}" \
    || die "Post-check failed: execve user_commands audit rules missing."
  grep -q 'APT::Periodic::Unattended-Upgrade "1";' "${APT_AUTO_FILE}" || die "Post-check failed: unattended-upgrades periodic config missing."

  local syncookies ip_forward
  syncookies="$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || echo "?")"
  ip_forward="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "?")"
  [[ "${syncookies}" == "1" ]] || die "Post-check failed: tcp_syncookies is ${syncookies}, expected 1."
  [[ "${ip_forward}" == "1" ]] || die "Post-check failed: ip_forward is ${ip_forward}, expected 1."

  local current_timezone
  current_timezone="$(timedatectl show --property=Timezone --value 2>/dev/null || true)"
  [[ "${current_timezone}" == "${TIMEZONE}" ]] \
    || die "Post-check failed: timezone is ${current_timezone:-unknown}, expected ${TIMEZONE}."

  if command -v tailscale >/dev/null 2>&1; then
    if tailscale status --json >/dev/null 2>&1; then
      local run_ssh_pref
      run_ssh_pref="$(tailscale_runssh_pref_value 5 1)"
      [[ "${run_ssh_pref}" == "false" ]] \
        || die "Post-check failed: tailscale RunSSH is ${run_ssh_pref:-unknown}, expected false."
    elif is_true "${INSTALL_TAILSCALE}"; then
      die "Post-check failed: tailscale CLI is present but status is unavailable after INSTALL_TAILSCALE=true."
    else
      warn "Post-check: tailscale CLI present but status unavailable; skipping RunSSH verification because INSTALL_TAILSCALE=false."
    fi
  elif is_true "${INSTALL_TAILSCALE}"; then
    die "Post-check failed: tailscale CLI not found after INSTALL_TAILSCALE=true."
  else
    warn "Post-check: tailscale CLI not found; skipping RunSSH verification because INSTALL_TAILSCALE=false."
  fi

  if [[ -f "${APPORT_DEFAULT_FILE}" ]]; then
    local apport_enabled
    apport_enabled="$(awk -F= '/^[[:space:]]*enabled[[:space:]]*=/{gsub(/[[:space:]]/, "", $2); print $2; exit}' "${APPORT_DEFAULT_FILE}" || true)"
    [[ "${apport_enabled}" == "0" ]] \
      || die "Post-check failed: apport enabled=${apport_enabled:-unknown}, expected 0."
  fi
  if unit_available "apport.service" && systemctl is-active --quiet apport.service 2>/dev/null; then
    die "Post-check failed: apport.service is active."
  fi

  systemctl is-active --quiet fail2ban || die "Post-check failed: fail2ban is not active."
  if unit_available "rsyslog.service"; then
    systemctl is-active --quiet rsyslog || die "Post-check failed: rsyslog is not active."
  else
    warn "Post-check: rsyslog.service not installed; skipping active-state verification."
  fi
  assert_rsyslog_posture

  [[ -f /etc/issue.net ]] || die "Post-check failed: /etc/issue.net missing."

  journalctl --disk-usage || true

  if command -v aa-status >/dev/null 2>&1; then
    if ! aa-status --enabled 2>/dev/null; then
      warn "AppArmor is installed but not enabled. Ubuntu 24.04 should have it active by default."
    fi
  else
    warn "aa-status not found; cannot verify AppArmor status."
  fi

  # Dashboard UFW restriction verification (UFW-based; does not check socket binding)
  if is_true "${BIND_DASHBOARD_TO_TAILSCALE}"; then
    log "Verifying Coolify dashboard UFW rules on ${TAILSCALE_IFACE}..."
    if command -v ufw >/dev/null 2>&1; then
      if ufw status | grep -q "8000.*on ${TAILSCALE_IFACE}"; then
        log "PASS: UFW rule for port 8000 on ${TAILSCALE_IFACE} is present"
      else
        warn "UFW rule for port 8000 on ${TAILSCALE_IFACE} not found. Check: ufw status"
      fi
      if ufw status | grep -q "6001.*on ${TAILSCALE_IFACE}"; then
        log "PASS: UFW rule for port 6001 on ${TAILSCALE_IFACE} is present"
      else
        warn "UFW rule for port 6001 on ${TAILSCALE_IFACE} not found. Check: ufw status"
      fi
      if ufw status | grep -q "6002.*on ${TAILSCALE_IFACE}"; then
        log "PASS: UFW rule for port 6002 on ${TAILSCALE_IFACE} is present"
      else
        warn "UFW rule for port 6002 on ${TAILSCALE_IFACE} not found. Check: ufw status"
      fi
    fi

    log "External dashboard exposure is validated from off-host; skipping host-local public-IP probe."
  fi
}

write_state() {
  local cidr_csv=""
  local tmp_state=""
  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: write ${STATE_FILE}"
    return 0
  fi

  cidr_csv="$(IFS=,; echo "${DOCKER_SSH_CIDRS[*]}")"

  install -d -m 0750 "${STATE_DIR}"
  tmp_state="$(mktemp)"
  cat > "${tmp_state}" <<EOF
script_version=${SCRIPT_VERSION}
applied_at=$(date -Iseconds)
admin_user=${ADMIN_USER}
domain=${DOMAIN}
wan_iface=${WAN_IFACE}
ssh_port=${SSH_PORT}
tailscale_cidr=${TAILSCALE_CIDR}
tunnel_mode=${TUNNEL_MODE}
swap_size=${SWAP_SIZE}
journal_retention=${JOURNAL_RETENTION}
update_profile=${UPDATE_PROFILE}
timezone=${TIMEZONE}
docker_present=${DOCKER_PRESENT}
docker_rules_applied=${DOCKER_RULES_APPLIED}
strict_docker_ssh_cidrs=${STRICT_DOCKER_SSH_CIDRS}
docker_ssh_cidrs=${cidr_csv}
docker_nproc_hard=${DOCKER_NPROC_HARD}
docker_nproc_soft=${DOCKER_NPROC_SOFT}
allowed_privileged_containers=${ALLOWED_PRIVILEGED_CONTAINERS}
tailscale_direct_wan=${TAILSCALE_DIRECT_WAN}
bind_dashboard_to_tailscale=${BIND_DASHBOARD_TO_TAILSCALE}
install_tailscale=${INSTALL_TAILSCALE}
EOF

  if is_true "${BIND_DASHBOARD_TO_TAILSCALE}" && [[ -n "${DETECTED_TAILSCALE_IP}" ]]; then
    echo "tailscale_ip=${DETECTED_TAILSCALE_IP}" >> "${tmp_state}"
  fi

  if command -v flock >/dev/null 2>&1; then
    exec 9>"${STATE_LOCK_FILE}"
    flock 9
  fi

  install -m 0640 "${tmp_state}" "${STATE_FILE}"
  rm -f "${tmp_state}"

  if command -v flock >/dev/null 2>&1; then
    flock -u 9 || true
    exec 9>&-
  fi
}

generate_report() {
  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: write ${REPORT_FILE}"
    return 0
  fi

  local tailscale_iface_present
  local ufw_active
  local ssh_root_disabled
  local ssh_password_disabled
  local journald_persistent
  local auditd_enabled
  local audit_rules_loaded
  local docker_drop_rule
  local docker_drop_rule_v6
  local sysctl_syncookies
  local fail2ban_active
  local tailscale_runssh_disabled
  local banner_present
  local docker_ssh_cidrs_csv
  local docker_sock_world_writable="false"
  local admin_in_docker_group="false"

  tailscale_iface_present="$(bool_cmd ip link show "${TAILSCALE_IFACE}")"
  ufw_active="$(ufw status | grep -q "^Status: active$" && echo "true" || echo "false")"
  local ssh_root_local_only
  ssh_root_disabled="$(sshd -T 2>/dev/null | grep -q "^permitrootlogin no$" && echo "true" || echo "false")"
  ssh_root_local_only="$(sshd -T -C addr=127.0.0.1,user=root,host=localhost,laddr=127.0.0.1 2>/dev/null | grep -qE "^permitrootlogin (prohibit-password|without-password)$" && echo "true" || echo "false")"
  ssh_password_disabled="$(sshd -T 2>/dev/null | grep -q "^passwordauthentication no$" && echo "true" || echo "false")"
  journald_persistent="$(grep -q "^Storage=persistent$" "${JOURNALD_DROPIN_FILE}" && echo "true" || echo "false")"
  auditd_enabled="$(systemctl is-enabled auditd >/dev/null 2>&1 && echo "true" || echo "false")"
  audit_rules_loaded="$(auditctl -l | grep -q "identity" && echo "true" || echo "false")"
  docker_drop_rule="$(iptables -t filter -S DOCKER-USER 2>/dev/null | grep -q "coolify-hardening-wan-drop" && echo "true" || echo "false")"
  docker_drop_rule_v6="$(ip6tables -t filter -S DOCKER-USER 2>/dev/null | grep -q "coolify-hardening-wan-drop6" && echo "true" || echo "false")"
  sysctl_syncookies="$([[ "$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)" == "1" ]] && echo "true" || echo "false")"
  local sysctl_bbr
  sysctl_bbr="$([[ "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)" == "bbr" ]] && echo "true" || echo "false")"
  local timesync_ntp
  timesync_ntp="$([[ "$(timedatectl show --property=NTP --value 2>/dev/null)" == "yes" ]] && echo "true" || echo "false")"
  local swap_active
  swap_active="$(swapon --show --noheadings 2>/dev/null | grep -q . && echo "true" || echo "false")"
  fail2ban_active="$(systemctl is-active --quiet fail2ban && echo "true" || echo "false")"
  tailscale_runssh_disabled="$([[ "$(tailscale_runssh_pref_value 5 1)" == "false" ]] && echo "true" || echo "false")"
  banner_present="$([[ -f /etc/issue.net ]] && echo "true" || echo "false")"
  docker_ssh_cidrs_csv="$(IFS=,; echo "${DOCKER_SSH_CIDRS[*]}")"

  if [[ "${DOCKER_PRESENT}" == "true" ]]; then
    if [[ -S /var/run/docker.sock ]]; then
      local docker_sock_mode docker_sock_other
      docker_sock_mode="$(stat -c '%a' /var/run/docker.sock 2>/dev/null || echo "")"
      if [[ -n "${docker_sock_mode}" ]]; then
        docker_sock_other="${docker_sock_mode: -1}"
        if [[ "${docker_sock_other}" =~ ^[0-7]$ ]] && (( (10#${docker_sock_other} & 2) != 0 )); then
          docker_sock_world_writable="true"
        fi
      fi
    fi
    if getent group docker >/dev/null 2>&1 && id -nG "${ADMIN_USER}" 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
      admin_in_docker_group="true"
    fi
  fi

  # Dashboard UFW restriction check (UFW-based; security enforced by UFW not socket binding)
  local coolify_dashboard_bound="false"
  local coolify_dashboard_ip=""
  if is_true "${BIND_DASHBOARD_TO_TAILSCALE}"; then
    coolify_dashboard_ip="${DETECTED_TAILSCALE_IP:-}"
    # Check if UFW rule for port 8000 on tailscale0 is present
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "8000.*on ${TAILSCALE_IFACE}"; then
      coolify_dashboard_bound="true"
    fi
  fi

  jq -n \
    --arg generated_at "$(date -Iseconds)" \
    --arg script_version "${SCRIPT_VERSION}" \
    --arg os_version "${OS_VERSION}" \
    --arg admin_user "${ADMIN_USER}" \
    --arg wan_iface "${WAN_IFACE}" \
    --arg tailscale_iface "${TAILSCALE_IFACE}" \
    --arg tailscale_cidr_hint "${TAILSCALE_CIDR}" \
    --argjson ssh_port "${SSH_PORT}" \
    --argjson tunnel_mode "$(is_true "${TUNNEL_MODE}" && echo true || echo false)" \
    --arg swap_size "${SWAP_SIZE:-2G}" \
    --arg journal_retention "${JOURNAL_RETENTION}" \
    --arg update_profile "${UPDATE_PROFILE}" \
    --arg timezone "${TIMEZONE}" \
    --argjson auto_reboot_requested "$(is_true "${ENABLE_AUTO_REBOOT}" && echo true || echo false)" \
    --arg auto_reboot_time "${AUTO_REBOOT_TIME}" \
    --argjson strict_docker_ssh_cidrs "$(is_true "${STRICT_DOCKER_SSH_CIDRS}" && echo true || echo false)" \
    --arg docker_ssh_cidrs "${docker_ssh_cidrs_csv}" \
    --argjson docker_nproc_hard "${DOCKER_NPROC_HARD}" \
    --argjson docker_nproc_soft "${DOCKER_NPROC_SOFT}" \
    --argjson tailscale_direct_wan "$(is_true "${TAILSCALE_DIRECT_WAN}" && echo true || echo false)" \
    --argjson bind_dashboard_to_tailscale "$(is_true "${BIND_DASHBOARD_TO_TAILSCALE}" && echo true || echo false)" \
    --argjson install_tailscale "$(is_true "${INSTALL_TAILSCALE}" && echo true || echo false)" \
    --arg tailscale_ip "${DETECTED_TAILSCALE_IP:-}" \
    --argjson dry_run "$(is_true "${DRY_RUN}" && echo true || echo false)" \
    --argjson tailscale_iface_present "${tailscale_iface_present}" \
    --argjson ufw_active "${ufw_active}" \
    --argjson ssh_root_login_disabled "${ssh_root_disabled}" \
    --argjson ssh_root_local_only_key_auth "${ssh_root_local_only}" \
    --argjson ssh_password_auth_disabled "${ssh_password_disabled}" \
    --argjson journald_persistent "${journald_persistent}" \
    --argjson auditd_enabled "${auditd_enabled}" \
    --argjson audit_rules_loaded "${audit_rules_loaded}" \
    --argjson docker_user_drop_rule_v4 "${docker_drop_rule}" \
    --argjson docker_user_drop_rule_v6 "${docker_drop_rule_v6}" \
    --argjson docker_sock_world_writable "${docker_sock_world_writable}" \
    --argjson admin_user_in_docker_group "${admin_in_docker_group}" \
    --argjson sysctl_syncookies "${sysctl_syncookies}" \
    --argjson sysctl_bbr "${sysctl_bbr}" \
    --argjson timesync_ntp "${timesync_ntp}" \
    --argjson swap_active "${swap_active}" \
    --argjson fail2ban_active "${fail2ban_active}" \
    --argjson tailscale_runssh_disabled "${tailscale_runssh_disabled}" \
    --argjson banner_present "${banner_present}" \
    --argjson coolify_dashboard_bound_to_tailscale "${coolify_dashboard_bound}" \
    '{
      generated_at: $generated_at,
      script_version: $script_version,
      os_version: $os_version,
      admin_user: $admin_user,
      wan_iface: $wan_iface,
      tailscale_iface: $tailscale_iface,
      tailscale_cidr_hint: $tailscale_cidr_hint,
      ssh_port: $ssh_port,
      tunnel_mode: $tunnel_mode,
      swap_size: $swap_size,
      journal_retention: $journal_retention,
      update_profile: $update_profile,
      timezone: $timezone,
      auto_reboot_requested: $auto_reboot_requested,
      auto_reboot_time: $auto_reboot_time,
      strict_docker_ssh_cidrs: $strict_docker_ssh_cidrs,
      docker_ssh_cidrs: $docker_ssh_cidrs,
      docker_nproc_hard: $docker_nproc_hard,
      docker_nproc_soft: $docker_nproc_soft,
      tailscale_direct_wan: $tailscale_direct_wan,
      bind_dashboard_to_tailscale: $bind_dashboard_to_tailscale,
      install_tailscale: $install_tailscale,
      tailscale_ip: $tailscale_ip,
      dry_run: $dry_run,
      checks: {
        tailscale_iface_present: $tailscale_iface_present,
        ufw_active: $ufw_active,
        ssh_root_login_disabled: $ssh_root_login_disabled,
        ssh_root_local_only_key_auth: $ssh_root_local_only_key_auth,
        ssh_password_auth_disabled: $ssh_password_auth_disabled,
        journald_persistent: $journald_persistent,
        auditd_enabled: $auditd_enabled,
        audit_rules_loaded: $audit_rules_loaded,
        docker_user_drop_rule_v4: $docker_user_drop_rule_v4,
        docker_user_drop_rule_v6: $docker_user_drop_rule_v6,
        docker_sock_world_writable: $docker_sock_world_writable,
        admin_user_in_docker_group: $admin_user_in_docker_group,
        sysctl_syncookies: $sysctl_syncookies,
        sysctl_bbr: $sysctl_bbr,
        timesync_ntp: $timesync_ntp,
        swap_active: $swap_active,
        fail2ban_active: $fail2ban_active,
        tailscale_runssh_disabled: $tailscale_runssh_disabled,
        banner_present: $banner_present,
        coolify_dashboard_bound_to_tailscale: $coolify_dashboard_bound_to_tailscale
      }
    }' > "${REPORT_FILE}"

  chmod 0600 "${REPORT_FILE}"
}

configure_hardening_validation_timer() {
  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: would install hardening-validate.timer (daily validate_hardening.sh run)."
    return 0
  fi

  # Locate validate_hardening.sh relative to this script, with multiple fallbacks
  local script_dir validate_src validate_dest
  if [[ -n "${BASH_SOURCE[0]:-}" ]]; then
    script_dir="$(cd "${BASH_SOURCE[0]%/*}" 2>/dev/null && pwd)" || {
      # Fallback 1: realpath (common on Linux)
      if command -v realpath >/dev/null 2>&1; then
        script_dir="$(dirname "$(realpath "${BASH_SOURCE[0]}")" 2>/dev/null)" || script_dir=""
      fi
      # Fallback 2: readlink -f (macOS/BSD)
      if [[ -z "${script_dir}" ]] && command -v readlink >/dev/null 2>&1; then
        script_dir="$(dirname "$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")")"
      fi
    }
  fi

  # Final fallback: use directory of script invocation
  script_dir="${script_dir:-$(pwd)}"

  validate_src="${script_dir}/validate_hardening.sh"
  validate_dest="/usr/local/sbin/validate-hardening"

  if [[ -f "${validate_src}" ]]; then
    install -m 0750 -o root -g root "${validate_src}" "${validate_dest}"
    log "Installed ${validate_src} → ${validate_dest}"
  else
    warn "validate_hardening.sh not found at ${validate_src}; skipping timer install."
    return 0
  fi

  cat > /etc/systemd/system/hardening-validate.service <<'SVCEOF'
[Unit]
Description=Run hardening validation checks
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/validate-hardening
SVCEOF

  cat > /etc/systemd/system/hardening-validate.timer <<'TIMEREOF'
[Unit]
Description=Daily hardening validation

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
TIMEREOF

  run systemctl daemon-reload
  run systemctl enable --now hardening-validate.timer
  log "hardening-validate.timer enabled (runs validate_hardening.sh daily)."
}

configure_docker_ssh_cidr_sync_timer() {
  if ! is_true "${STRICT_DOCKER_SSH_CIDRS}"; then
    if is_true "${DRY_RUN}"; then
      log "DRY-RUN: would disable docker-ssh-cidr-sync.timer in compatibility CIDR mode."
      return 0
    fi
    systemctl disable --now docker-ssh-cidr-sync.timer 2>/dev/null || true
    rm -f "${DOCKER_SSH_CIDR_SYNC_SERVICE}" "${DOCKER_SSH_CIDR_SYNC_TIMER}" "${DOCKER_SSH_CIDR_SYNC_SCRIPT}" 2>/dev/null || true
    run systemctl daemon-reload
    return 0
  fi

  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: would install docker-ssh-cidr-sync.timer."
    return 0
  fi

  write_file "${DOCKER_SSH_CIDR_SYNC_SCRIPT}" "0750" "root" "root" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

STATE_FILE="/var/lib/bootstrap-hardening/state"
STATE_LOCK_FILE="${STATE_FILE}.lock"
SSH_DROPIN_FILE="/etc/ssh/sshd_config.d/00-coolify-hardening.conf"
RULE_COMMENT="coolify-hardening-ssh-docker-bridge"

[[ -f "${STATE_FILE}" ]] || exit 0

copy_state_file() {
  local dest="$1"
  if command -v flock >/dev/null 2>&1; then
    flock -s "${STATE_LOCK_FILE}" bash -ceu 'cat "$1" > "$2"' _ "${STATE_FILE}" "${dest}"
  else
    cat "${STATE_FILE}" > "${dest}"
  fi
}

update_state_docker_cidrs() {
  local cidr_csv="$1"
  local tmp_state
  tmp_state="$(mktemp)"

  if command -v flock >/dev/null 2>&1; then
    exec 9>"${STATE_LOCK_FILE}"
    flock 9
  fi

  awk -v cidr_csv="${cidr_csv}" '
    BEGIN { updated=0 }
    /^docker_ssh_cidrs=/ {
      print "docker_ssh_cidrs=" cidr_csv
      updated=1
      next
    }
    { print }
    END {
      if (!updated) print "docker_ssh_cidrs=" cidr_csv
    }
  ' "${STATE_FILE}" > "${tmp_state}"
  install -m 0640 "${tmp_state}" "${STATE_FILE}"
  rm -f "${tmp_state}"

  if command -v flock >/dev/null 2>&1; then
    flock -u 9 || true
    exec 9>&-
  fi
}

state_snapshot="$(mktemp)"
copy_state_file "${state_snapshot}"
# shellcheck disable=SC1090
source "${state_snapshot}"
rm -f "${state_snapshot}"

is_true() {
  case "${1,,}" in
    1|true|yes|y|on) return 0 ;;
    *) return 1 ;;
  esac
}

if ! is_true "${strict_docker_ssh_cidrs:-false}"; then
  exit 0
fi

admin_user="${admin_user:-}"
ssh_port="${ssh_port:-22}"
[[ -n "${admin_user}" ]] || exit 0
[[ "${ssh_port}" =~ ^[0-9]+$ ]] || ssh_port="22"

is_valid_cidr() {
  [[ "$1" =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/([0-9]|[12][0-9]|3[0-2])$ ]]
}

normalize_cidr() {
  python3 - "$1" <<'PY'
import ipaddress
import sys
try:
    net = ipaddress.ip_network(sys.argv[1], strict=False)
    if isinstance(net, ipaddress.IPv4Network):
        print(str(net))
except Exception:
    pass
PY
}

declare -a cidrs=()
declare -A seen=()

add_cidr() {
  local cidr="$1"
  local normalized
  [[ -n "${cidr}" ]] || return 0
  is_valid_cidr "${cidr}" || return 0
  normalized="$(normalize_cidr "${cidr}")"
  [[ -n "${normalized}" ]] || return 0
  if [[ -z "${seen[${normalized}]:-}" ]]; then
    cidrs+=("${normalized}")
    seen["${normalized}"]=1
  fi
}

if command -v docker >/dev/null 2>&1; then
  while IFS= read -r cidr; do
    add_cidr "${cidr}"
  done < <(
    docker network ls --filter driver=bridge -q 2>/dev/null \
      | xargs -r docker network inspect --format '{{range .IPAM.Config}}{{.Subnet}}{{"\n"}}{{end}}' 2>/dev/null \
      | awk 'NF' \
      | sort -u
  )
fi

if command -v ip >/dev/null 2>&1; then
  while IFS= read -r cidr; do
    add_cidr "${cidr}"
  done < <(
    ip -o -4 addr show 2>/dev/null \
      | awk '$2 ~ /^docker0$/ || $2 ~ /^br-[[:alnum:]]+$/ { print $4 }' \
      | awk 'NF' \
      | sort -u
  )
fi

if [[ ${#cidrs[@]} -eq 0 ]]; then
  IFS=',' read -r -a previous_cidrs <<< "${docker_ssh_cidrs:-10.0.0.0/8,172.16.0.0/12}"
  for cidr in "${previous_cidrs[@]}"; do
    cidr="${cidr//[[:space:]]/}"
    add_cidr "${cidr}"
  done
fi

[[ ${#cidrs[@]} -gt 0 ]] || exit 0

match_addresses="127.0.0.1,::1"
for cidr in "${cidrs[@]}"; do
  match_addresses+=",${cidr}"
done

if [[ -f "${SSH_DROPIN_FILE}" ]] && grep -q '^Match Address ' "${SSH_DROPIN_FILE}"; then
  desired_line="Match Address ${match_addresses}"
  current_line="$(grep -m1 '^Match Address ' "${SSH_DROPIN_FILE}" || true)"
  if [[ "${current_line}" != "${desired_line}" ]]; then
    tmp_dropin="$(mktemp)"
    backup_dropin="${SSH_DROPIN_FILE}.bak.$(date +%s)"
    cp -a "${SSH_DROPIN_FILE}" "${backup_dropin}"
    sed "0,/^Match Address /s|^Match Address .*|${desired_line}|" "${SSH_DROPIN_FILE}" > "${tmp_dropin}"
    install -m 0644 "${tmp_dropin}" "${SSH_DROPIN_FILE}"
    rm -f "${tmp_dropin}"
    if ! sshd -t; then
      cp -a "${backup_dropin}" "${SSH_DROPIN_FILE}"
      exit 1
    fi
    if systemctl is-active --quiet ssh 2>/dev/null; then
      systemctl reload ssh || systemctl restart ssh
    elif systemctl is-active --quiet sshd 2>/dev/null; then
      systemctl reload sshd || systemctl restart sshd
    fi
    rm -f "${SSH_DROPIN_FILE}".bak.*
  fi
fi

# Reconcile UFW Docker bridge SSH rules to current CIDRs.
if command -v ufw >/dev/null 2>&1; then
  IFS=',' read -r -a old_cidrs <<< "${docker_ssh_cidrs:-}"
  for old_cidr in "${old_cidrs[@]}"; do
    old_cidr="${old_cidr//[[:space:]]/}"
    [[ -n "${old_cidr}" ]] || continue
    # Delete tcp-specific rule
    ufw --force delete allow in proto tcp from "${old_cidr}" to any port "${ssh_port}" comment "${RULE_COMMENT}" >/dev/null 2>&1 || true
    # Delete orphaned non-tcp rule (try multiple syntaxes for compatibility)
    ufw --force delete allow in from "${old_cidr}" to any port "${ssh_port}" comment "${RULE_COMMENT}" >/dev/null 2>&1 || true
    ufw --force delete allow from "${old_cidr}" to any port "${ssh_port}" comment "${RULE_COMMENT}" >/dev/null 2>&1 || true
  done
  for cidr in "${cidrs[@]}"; do
    ufw allow in proto tcp from "${cidr}" to any port "${ssh_port}" comment "${RULE_COMMENT}" >/dev/null 2>&1 || true
  done
fi

cidr_csv="$(IFS=,; echo "${cidrs[*]}")"
update_state_docker_cidrs "${cidr_csv}"
EOF

  write_file "${DOCKER_SSH_CIDR_SYNC_SERVICE}" "0644" "root" "root" <<EOF
[Unit]
Description=Reconcile Docker bridge CIDRs in SSH/UFW hardening rules
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${DOCKER_SSH_CIDR_SYNC_SCRIPT}
EOF

  write_file "${DOCKER_SSH_CIDR_SYNC_TIMER}" "0644" "root" "root" <<'EOF'
[Unit]
Description=Periodic Docker bridge CIDR reconciliation for SSH hardening

[Timer]
OnBootSec=3min
OnUnitActiveSec=10min
Persistent=true

[Install]
WantedBy=timers.target
EOF

  run systemctl daemon-reload
  run systemctl enable --now docker-ssh-cidr-sync.timer
  run systemctl start docker-ssh-cidr-sync.service
  wait_for_systemd_unit_success "docker-ssh-cidr-sync.service" 15 2 \
    || die "docker-ssh-cidr-sync.service did not complete successfully."
  log "docker-ssh-cidr-sync.timer enabled (strict Docker SSH CIDR auto-reconcile)."
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
