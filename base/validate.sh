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

# base/validate.sh — Standalone health-check companion for base/bootstrap.sh
# Re-runnable: prints PASS/FAIL per check, exits 0 if all pass, 1 if any fail.
# Usage: sudo ./base/validate.sh [--json|--health-check]

STATE_FILE="/var/lib/server-hardening/state"
STATE_LOCK_FILE="${STATE_FILE}.lock"
JOURNALD_DROPIN="/etc/systemd/journald.conf.d/90-coolify-persistent.conf"
AUDITD_CONF="/etc/audit/auditd.conf"
HOSTS_FILE="${HOSTS_FILE:-/etc/hosts}"
JSON_MODE="false"
HEALTH_CHECK_MODE="false"
GATE_C_MODE="false"
IS_CONTAINER="false"

# shellcheck source=../overlays/docker-host/checks/_helpers.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../overlays/docker-host/checks/_helpers.sh"
# shellcheck source=../overlays/docker-host/checks/docker_user_check.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../overlays/docker-host/checks/docker_user_check.sh"
# shellcheck source=../overlays/docker-host/checks/docker_user_lifecycle_check.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../overlays/docker-host/checks/docker_user_lifecycle_check.sh"
# shellcheck source=../overlays/docker-host/checks/docker_ssh_cidr_sync_check.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../overlays/docker-host/checks/docker_ssh_cidr_sync_check.sh"
# shellcheck source=../overlays/docker-host/checks/docker_daemon_check.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../overlays/docker-host/checks/docker_daemon_check.sh"
# shellcheck source=../overlays/docker-host/checks/docker_trust_boundary_check.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../overlays/docker-host/checks/docker_trust_boundary_check.sh"

# shellcheck source=./checks/_runtime.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/checks/_runtime.sh"
# shellcheck source=./checks/ssh_check.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/checks/ssh_check.sh"
# shellcheck source=./checks/ufw_check.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/checks/ufw_check.sh"
# shellcheck source=./checks/sysctl_check.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/checks/sysctl_check.sh"
# shellcheck source=./checks/fail2ban_check.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/checks/fail2ban_check.sh"
# shellcheck source=./checks/auditd_check.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/checks/auditd_check.sh"
# shellcheck source=./checks/journald_check.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/checks/journald_check.sh"
# shellcheck source=./checks/rsyslog_check.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/checks/rsyslog_check.sh"
# shellcheck source=./checks/timesync_check.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/checks/timesync_check.sh"
# shellcheck source=./checks/timezone_check.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/checks/timezone_check.sh"
# shellcheck source=./checks/swap_check.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/checks/swap_check.sh"
# shellcheck source=./checks/bootloader_check.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/checks/bootloader_check.sh"
# shellcheck source=./checks/reboot_required_check.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/checks/reboot_required_check.sh"
# shellcheck source=./checks/banner_check.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/checks/banner_check.sh"
# shellcheck source=./checks/admin_sudo_check.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/checks/admin_sudo_check.sh"
# shellcheck source=./checks/apparmor_check.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/checks/apparmor_check.sh"
# shellcheck source=./checks/disabled_services_check.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/checks/disabled_services_check.sh"
# shellcheck source=./checks/apport_check.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/checks/apport_check.sh"
# shellcheck source=./checks/cron_check.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/checks/cron_check.sh"
# shellcheck source=./checks/networkd_wait_online_check.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/checks/networkd_wait_online_check.sh"
# shellcheck source=./checks/tailscale_check.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/checks/tailscale_check.sh"
# shellcheck source=../overlays/coolify/coolify-common.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../overlays/coolify/coolify-common.sh"
# shellcheck source=../overlays/coolify/checks/coolify_binding_check.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../overlays/coolify/checks/coolify_binding_check.sh"
# shellcheck source=../overlays/coolify/checks/unattended_upgrades_check.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../overlays/coolify/checks/unattended_upgrades_check.sh"
# shellcheck source=../overlays/coolify/checks/coolify_ssh_check.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../overlays/coolify/checks/coolify_ssh_check.sh"
# shellcheck source=../overlays/coolify/checks/cloudflared_check.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../overlays/coolify/checks/cloudflared_check.sh"
# shellcheck source=../overlays/coolify/checks/coolify_container_check.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../overlays/coolify/checks/coolify_container_check.sh"
# shellcheck source=../overlays/coolify/checks/coolify_instance_settings_check.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../overlays/coolify/checks/coolify_instance_settings_check.sh"
# shellcheck source=../overlays/coolify/checks/validate_timer_check.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../overlays/coolify/checks/validate_timer_check.sh"



PASS_COUNT=0
FAIL_COUNT=0
INFO_COUNT=0
declare -a RESULTS=()





# Load state file for context (non-fatal if missing)
ADMIN_USER=""
DOMAIN=""
SSH_PORT="22"
TUNNEL_MODE="false"
WAN_IFACE=""
TAILSCALE_IFACE="tailscale0"
BIND_DASHBOARD_TO_TAILSCALE="false"
TAILSCALE_IP=""
TAILSCALE_CIDR="100.64.0.0/10"
STRICT_DOCKER_SSH_CIDRS="false"
DOCKER_SSH_CIDRS="10.0.0.0/8,172.16.0.0/12"
ALLOWED_PRIVILEGED_CONTAINERS=""
TAILSCALE_DIRECT_WAN="auto"
UPDATE_PROFILE=""
DOCKER_PRESENT="false"
DOCKER_RULES_APPLIED="false"
CONFIGURED_TIMEZONE=""
COOLIFY_ENV_FILE="/data/coolify/source/.env"
DOCKER_SSH_CIDR_SYNC_SCRIPT="/usr/local/sbin/docker-ssh-cidr-sync.sh"
DOCKER_SSH_CIDR_SYNC_SERVICE="docker-ssh-cidr-sync.service"
DOCKER_SSH_CIDR_SYNC_TIMER="docker-ssh-cidr-sync.timer"
FAIL2BAN_LOCAL_FILE="/etc/fail2ban/fail2ban.local"
APPORT_DEFAULT_FILE="/etc/default/apport"
CRON_EXTRA_OPTS_DROPIN="/etc/systemd/system/cron.service.d/10-extra-opts.conf"
TAILSCALED_NOTIFY_DROPIN="/etc/systemd/system/tailscaled.service.d/10-notify-access.conf"
NETWORKD_WAIT_ONLINE_DROPIN="/etc/systemd/system/systemd-networkd-wait-online.service.d/10-any-timeout.conf"
APT_HELPER_BIN="${APT_HELPER_BIN:-/usr/lib/apt/apt-helper}"










# ── SSH effective config ──


# ── UFW ──


# ── DOCKER-USER iptables (IPv4 + IPv6) ──


# ── docker-user-hardening service lifecycle ──


# ── docker-ssh-cidr-sync lifecycle (strict CIDR mode) ──


# ── Sysctl ──


# ── fail2ban ──


# ── auditd ──


# ── journald ──




# ── NTP / Timesync ──



# ── Swap ──





# ── Banner ──


# ── Admin sudo access ──


# ── Docker daemon.json ──
# Hardening owns: log-driver, log-opts, live-restore, default-ipc-mode,
#   storage-driver, default-ulimits. Coolify may add: default-address-pools.
# Using json-file driver to match Coolify's expectation for compatibility.


# ── Docker daemon trust-boundary checks ──


# ── AppArmor ──


# ── Disabled services ──





# ── Tailscale interface ──


# ── Coolify split-horizon binding ──


main() {
  parse_cli_args "$@"
  detect_container_runtime
  load_state_context

  [[ "$(id -u)" -eq 0 ]] || { echo "Run as root." >&2; exit 1; }

  if [[ "${JSON_MODE}" == "false" && "${HEALTH_CHECK_MODE}" != "true" ]]; then
    printf '%-6s %-45s %s\n' "STATUS" "CHECK" "DETAIL"
    printf '%s\n' "--------------------------------------------------------------"
  fi

  ssh_check
  ufw_check
  docker_user_check
  docker_user_lifecycle_check
  docker_ssh_cidr_sync_check
  docker_daemon_check
  docker_trust_boundary_check
  sysctl_check
  fail2ban_check
  auditd_check
  unattended_upgrades_check
  reboot_required_check
  journald_check
  rsyslog_check
  timesync_check
  timezone_check
  swap_check
  bootloader_check
  banner_check
  admin_sudo_check
  apparmor_check
  disabled_services_check
  apport_check
  cron_check
  networkd_wait_online_check
  private_domain_hosts_check
  tailscale_check
  coolify_binding_check
  if [[ "${GATE_C_MODE}" == "true" ]]; then
    record "INFO" "gate-c: coolify runtime checks" "skipped in --gate-c mode"
    record "INFO" "gate-c: cloudflared checks" "skipped in --gate-c mode"
  else
    coolify_ssh_check
    coolify_container_check
    coolify_instance_settings_check
    cloudflared_check
  fi
  validate_timer_check
  listening_ports_info

  if [[ "${HEALTH_CHECK_MODE}" == "true" ]]; then
    if ((FAIL_COUNT > 0)); then
      echo "UNHEALTHY"
      exit 1
    fi
    echo "HEALTHY"
    exit 0
  elif [[ "${JSON_MODE}" == "true" ]]; then
    checks_json='[]'
    if ((${#RESULTS[@]} > 0)); then
      checks_json="$(printf '%s\n' "${RESULTS[@]}" | jq -s '.')"
    fi
    jq -nc \
      --argjson pass "${PASS_COUNT}" \
      --argjson fail "${FAIL_COUNT}" \
      --argjson info "${INFO_COUNT}" \
      --argjson checks "${checks_json}" \
      '{pass:$pass,fail:$fail,info:$info,checks:$checks}'
  else
    printf '%s\n' "--------------------------------------------------------------"
    printf 'Summary: %d PASS, %d FAIL, %d INFO\n' "${PASS_COUNT}" "${FAIL_COUNT}" "${INFO_COUNT}"
  fi

  if ((FAIL_COUNT > 0)); then
    exit 1
  fi
  exit 0
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
