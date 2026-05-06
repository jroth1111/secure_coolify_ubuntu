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

# validate_hardening.sh — Standalone health-check companion for bootstrap_hardening.sh
# Re-runnable: prints PASS/FAIL per check, exits 0 if all pass, 1 if any fail.
# Usage: sudo ./validate_hardening.sh [--json|--health-check]

STATE_FILE="/var/lib/bootstrap-hardening/state"
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

coolify_binding_check() {
  # Skip if binding restriction was not configured
  if ! is_true "${BIND_DASHBOARD_TO_TAILSCALE}"; then
    record "INFO" "coolify: dashboard UFW restriction" "not configured (use --bind-dashboard-to-tailscale)"
    return 0
  fi

  # Dashboard Tailscale restriction is enforced via UFW rules on tailscale0, not by
  # socket binding (APP_PORT=IP:port breaks Coolify's expose: directive). Check UFW rules.

  if ! command -v ufw >/dev/null 2>&1; then
    record "FAIL" "coolify: ufw" "ufw command not found"
    return 0
  fi

  local ufw_out
  ufw_out="$(ufw status 2>/dev/null)" || true

  # Check UFW rule for port 8000 on tailscale0
  if echo "${ufw_out}" | grep -q "8000.*on ${TAILSCALE_IFACE}"; then
    record "PASS" "coolify: UFW rule port 8000 on ${TAILSCALE_IFACE}"
  else
    record "FAIL" "coolify: UFW rule port 8000" "rule for port 8000 on ${TAILSCALE_IFACE} missing"
  fi

  # Check UFW rule for port 6001 on tailscale0
  if echo "${ufw_out}" | grep -q "6001.*on ${TAILSCALE_IFACE}"; then
    record "PASS" "coolify: UFW rule port 6001 on ${TAILSCALE_IFACE}"
  else
    record "INFO" "coolify: UFW rule port 6001" "rule for port 6001 on ${TAILSCALE_IFACE} missing (Soketi may not be in use)"
  fi

  # Check UFW rule for port 6002 on tailscale0
  if echo "${ufw_out}" | grep -q "6002.*on ${TAILSCALE_IFACE}"; then
    record "PASS" "coolify: UFW rule port 6002 on ${TAILSCALE_IFACE}"
  else
    record "INFO" "coolify: UFW rule port 6002" "rule for port 6002 on ${TAILSCALE_IFACE} missing (terminal may not be in use)"
  fi

  # Check port 8000 is listening (any address — UFW restricts which interfaces can reach it)
  local bound_8000
  bound_8000="$(ss -tlnp 2>/dev/null | grep ':8000 ' || true)"
  if [[ -n "${bound_8000}" ]]; then
    record "PASS" "coolify: port 8000 listening"
  else
    record "INFO" "coolify: port 8000" "not yet listening (Coolify may still be starting)"
  fi

  # Note: nc-based self-connect tests cannot validate public exposure — the kernel
  # routes server→own-public-IP locally, bypassing UFW INPUT rules entirely.
  # Public port exposure is validated via UFW rule inspection in ufw_check() instead.
  # External connectivity tests (Gate E/F in deploy.sh) verify from the operator machine.

  # Verify UFW binding-guard timer is active (periodically re-applies UFW rules if removed)
  if systemctl is-active --quiet coolify-binding-guard.timer 2>/dev/null; then
    record "PASS" "coolify: UFW binding-guard timer active"
  else
    record "FAIL" "coolify: UFW binding-guard timer" "not active — UFW rule drift may go undetected"
  fi
}

# ── unattended-upgrades coverage ──

unattended_upgrades_check() {
  local apt_local="/etc/apt/apt.conf.d/52unattended-upgrades-local"
  local security_origin='origin=Ubuntu,codename=${distro_codename}-security,label=Ubuntu'
  local updates_origin='origin=Ubuntu,codename=${distro_codename}-updates,label=Ubuntu'
  local docker_origin_archive='origin=Docker,label=Docker CE,archive=${distro_codename},component=stable'
  local docker_origin_suite='origin=Docker,label=Docker CE,suite=${distro_codename},component=stable'
  local profile="${UPDATE_PROFILE:-}"

  if [[ ! -f "${apt_local}" ]]; then
    record "FAIL" "auto-updates: local config" "not found at ${apt_local}"
    return
  fi

  if [[ -z "${profile}" ]]; then
    profile="$(infer_update_profile "${apt_local}")"
    record "INFO" "auto-updates: profile" "state missing update_profile; inferred ${profile} from local config"
  fi

  case "${profile}" in
    security-only|balanced) ;;
    *)
      record "FAIL" "auto-updates: profile" "unsupported profile '${profile}'"
      return
      ;;
  esac

  if grep -qF "${security_origin}" "${apt_local}"; then
    record "PASS" "auto-updates: Ubuntu security origin covered"
  else
    record "FAIL" "auto-updates: Ubuntu security origin" "not in origins pattern"
  fi

  if [[ "${profile}" == "balanced" ]]; then
    if grep -qF "${updates_origin}" "${apt_local}"; then
      record "PASS" "auto-updates: Ubuntu updates origin covered"
    else
      record "FAIL" "auto-updates: Ubuntu updates origin" "missing for balanced profile"
    fi

    if grep -qF "${docker_origin_archive}" "${apt_local}" || grep -qF "${docker_origin_suite}" "${apt_local}"; then
      record "PASS" "auto-updates: Docker CE origin pinned to stable"
    elif grep -q "origin=Docker,label=Docker CE" "${apt_local}"; then
      record "FAIL" "auto-updates: Docker CE origin" "present but not pinned to archive/suite + component=stable"
    else
      record "FAIL" "auto-updates: Docker CE origin" "missing for balanced profile"
    fi
  else
    if grep -qF "${updates_origin}" "${apt_local}"; then
      record "FAIL" "auto-updates: Ubuntu updates origin" "present but profile is security-only"
    else
      record "PASS" "auto-updates: Ubuntu updates origin excluded (security-only)"
    fi

    if grep -qF "${docker_origin_archive}" "${apt_local}" \
      || grep -qF "${docker_origin_suite}" "${apt_local}" \
      || grep -q "origin=Docker,label=Docker CE" "${apt_local}"; then
      record "FAIL" "auto-updates: Docker CE origin" "present but profile is security-only"
    else
      record "PASS" "auto-updates: Docker CE origin excluded (security-only)"
    fi
  fi

  if grep -q 'Unattended-Upgrade::Automatic-Reboot' "${apt_local}"; then
    record "PASS" "auto-updates: reboot policy configured"
  else
    record "FAIL" "auto-updates: reboot policy" "not configured"
  fi

  # Functional: verify apt timers are actually running (config alone doesn't prove execution).
  for timer in apt-daily.timer apt-daily-upgrade.timer; do
    if systemctl is-active --quiet "${timer}" 2>/dev/null; then
      record "PASS" "auto-updates: ${timer} active"
    else
      record "FAIL" "auto-updates: ${timer}" "timer not active — unattended-upgrades will not run"
    fi
  done

  # Verify apt timers have Persistent=false to prevent boot-time catch-up blocking package ops.
  # See: https://documentation.ubuntu.com/server/how-to/software/automatic-updates/
  for timer in apt-daily.timer apt-daily-upgrade.timer; do
    local override_file="/etc/systemd/system/${timer}.d/override.conf"
    if [[ -f "${override_file}" ]] && grep -q "Persistent=false" "${override_file}"; then
      record "PASS" "auto-updates: ${timer} Persistent=false"
    else
      record "FAIL" "auto-updates: ${timer} Persistent" \
        "override missing — boot-time catch-up may block package operations"
    fi
  done
}

# ── Listening ports (informational) ──


# ── Coolify SSH access to localhost ──
# Gate-C safe: all checks are skipped if Coolify is not yet installed.

coolify_ssh_check() {
  local ssh_dir="/data/coolify/ssh/keys"
  local coolify_env="/data/coolify/source/.env"

  # Gate-C safe: if Coolify environment is not present yet, treat this as
  # pre-install state and skip SSH key checks.
  if [[ ! -f "${coolify_env}" ]]; then
    return 0
  fi

  # Skip entirely if Coolify hasn't been installed yet (Gate C runs before install)
  if [[ ! -d "${ssh_dir}" ]]; then
    return 0
  fi

  local keyfile
  keyfile="$(ls "${ssh_dir}"/ssh_key@* "${ssh_dir}"/id.root@* 2>/dev/null | head -1 || true)"
  if [[ -z "${keyfile}" ]]; then
    keyfile="$(find "${ssh_dir}" -maxdepth 1 -type f ! -name '*.pub' 2>/dev/null | head -1 || true)"
  fi
  if [[ -z "${keyfile}" ]]; then
    record "FAIL" "coolify: ssh key exists" "no private key file found in ${ssh_dir}"
    return 0
  fi
  record "PASS" "coolify: ssh key exists"

  # Derive the public key from the private key
  local pubkey
  pubkey=$(ssh-keygen -y -f "${keyfile}" 2>/dev/null || true)
  if [[ -z "${pubkey}" ]]; then
    record "FAIL" "coolify: ssh key readable" "ssh-keygen -y failed on ${keyfile}"
    return 0
  fi

  # Check authorized_keys exists and contains the key on its own line.
  # Match on key data (field 2) only — sshd ignores comment field 3+, and ssh-keygen -y
  # may output a different comment than what was written. A bare substring grep would
  # still match a concatenated line, so we compare against per-line field 2 extractions.
  local auth="/root/.ssh/authorized_keys"
  if [[ ! -f "${auth}" ]]; then
    record "FAIL" "coolify: key in root authorized_keys" "${auth} does not exist"
    return 0
  fi

  local key_data
  key_data=$(awk '{print $2}' <<< "${pubkey}")

  if awk '{print $2}' "${auth}" 2>/dev/null | grep -qxF "${key_data}"; then
    record "PASS" "coolify: key in root authorized_keys"
  else
    # Check for concatenation: key data appears but not as a standalone field
    if grep -qF "${key_data}" "${auth}" 2>/dev/null; then
      record "FAIL" "coolify: key in root authorized_keys" \
        "key present but not on its own line (concatenation bug) — rewrite ${auth}"
    else
      record "FAIL" "coolify: key in root authorized_keys" \
        "Coolify public key not found in ${auth}"
    fi
    return 0
  fi

  # Functional test 1: SSH as root to 127.0.0.1 using Coolify's key (host-side).
  # Tests key + sshd Match block from the host loopback perspective.
  local host_known_hosts
  host_known_hosts="$(mktemp /tmp/validate-hardening-host-known-hosts.XXXXXX)"
  if ssh \
      -o StrictHostKeyChecking=accept-new \
      -o UserKnownHostsFile="${host_known_hosts}" \
      -o ConnectTimeout=5 \
      -o BatchMode=yes \
      -o LogLevel=ERROR \
      -i "${keyfile}" \
      root@127.0.0.1 'exit 0' 2>/dev/null; then
    record "PASS" "coolify: root@127.0.0.1 SSH functional"
  else
    record "FAIL" "coolify: root@127.0.0.1 SSH functional" \
      "key auth failed — check sshd Match block and authorized_keys"
  fi
  rm -f "${host_known_hosts}"

  # Functional test 2: SSH from INSIDE the coolify container to host.docker.internal.
  # This is the exact path Coolify uses for 'This Machine'. Catches:
  #   - host.docker.internal not resolving (host-gateway bug on Linux Docker)
  #   - UFW blocking port 22 from Docker bridge subnets
  #   - sshd Match block not covering the Docker bridge address range
  if command -v docker >/dev/null 2>&1 && docker inspect coolify >/dev/null 2>&1; then
    local container_keyfile
    local container_known_hosts
    container_keyfile="/var/www/html/storage/app/ssh/keys/$(basename "${keyfile}")"
    container_known_hosts="/tmp/validate-hardening-container-known-hosts"
    if docker exec coolify \
        sh -c "rm -f '${container_known_hosts}' \
               && ssh -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile='${container_known_hosts}' \
               -o ConnectTimeout=5 -o BatchMode=yes -o LogLevel=ERROR \
               -i '${container_keyfile}' root@host.docker.internal 'exit 0' \
               && rm -f '${container_known_hosts}'" \
        2>/dev/null; then
      record "PASS" "coolify: container→host SSH via host.docker.internal"
    else
      record "FAIL" "coolify: container→host SSH via host.docker.internal" \
        "SSH from coolify container failed — check host.docker.internal in /etc/hosts, UFW Docker-bridge SSH rules, and sshd Match block"
      docker exec coolify sh -c "rm -f '${container_known_hosts}'" >/dev/null 2>&1 || true
    fi
  else
    record "INFO" "coolify: container→host SSH" "coolify container not running; skipped"
  fi
}

# ── cloudflared ──

cloudflared_check() {
  # Not installed at all — that is fine before Coolify deploy
  if ! systemctl list-unit-files --no-legend cloudflared.service 2>/dev/null | grep -q cloudflared \
      && ! command -v cloudflared >/dev/null 2>&1; then
    record "INFO" "cloudflared: not installed"
    return
  fi

  # Installed — now it must be active
  if systemctl is-active --quiet cloudflared 2>/dev/null; then
    record "PASS" "cloudflared: service active"
  else
    local svc_state
    svc_state="$(systemctl is-active cloudflared 2>/dev/null || echo "unknown")"
    record "FAIL" "cloudflared: service active" "state is ${svc_state}"
    return
  fi

  # cloudflared warns at startup when ping_group_range excludes gid 0.
  # Keep a sane range that includes root to avoid noisy ICMP proxy warnings.
  if command -v sysctl >/dev/null 2>&1; then
    local ping_group_range pg_lo pg_hi
    ping_group_range="$(sysctl -n net.ipv4.ping_group_range 2>/dev/null || true)"
    if [[ "${ping_group_range}" =~ ^[[:space:]]*([0-9]+)[[:space:]]+([0-9]+)[[:space:]]*$ ]]; then
      pg_lo="${BASH_REMATCH[1]}"
      pg_hi="${BASH_REMATCH[2]}"
      if (( pg_hi < pg_lo )); then
        record "FAIL" "cloudflared: ping_group_range" \
          "invalid range (${pg_lo} ${pg_hi}); expected ascending values including gid 0"
      elif (( pg_lo > 0 || pg_hi < 0 )); then
        record "FAIL" "cloudflared: ping_group_range" \
          "gid 0 excluded (${pg_lo} ${pg_hi}); cloudflared logs ICMP proxy warnings"
      else
        record "PASS" "cloudflared: ping_group_range includes gid 0 (${pg_lo} ${pg_hi})"
      fi
    else
      record "INFO" "cloudflared: ping_group_range" \
        "unable to parse net.ipv4.ping_group_range (${ping_group_range:-unknown})"
    fi
  else
    record "INFO" "cloudflared: ping_group_range" "sysctl not found; skipped"
  fi

  # Config file checks
  local config_file="${CLOUDFLARED_CONFIG_FILE:-/etc/cloudflared/config.yml}"
  if [[ ! -f "${config_file}" ]]; then
    record "FAIL" "cloudflared: config file" "${config_file} not found"
    return
  fi

  local tunnel_id
  tunnel_id="$(grep -m1 '^tunnel:' "${config_file}" | awk '{print $2}' || true)"
  if [[ -n "${tunnel_id}" ]]; then
    record "PASS" "cloudflared: tunnel ID configured"
  else
    record "FAIL" "cloudflared: tunnel ID" "not found in ${config_file}"
  fi

  # Wildcard app domains must route to Traefik (coolify-proxy) on port 80.
  if grep -qE 'localhost:80$|localhost:80[^0-9]|127\.0\.0\.1:80$|127\.0\.0\.1:80[^0-9]' "${config_file}"; then
    record "PASS" "cloudflared: ingress routes apps via Traefik (port 80)"
  else
    record "FAIL" "cloudflared: ingress app routing" \
      "no localhost:80 route — app domains will show dashboard instead of apps"
  fi

  # Private-only profile: dashboard/realtime/terminal must not be tunneled publicly.
  if grep -qE 'localhost:8000|127\.0\.0\.1:8000' "${config_file}"; then
    record "FAIL" "cloudflared: dashboard ingress disabled" \
      "found route to localhost:8000 — dashboard must stay Tailscale-only"
  else
    record "PASS" "cloudflared: dashboard ingress disabled"
  fi

  if grep -qE 'localhost:6001|127\.0\.0\.1:6001' "${config_file}"; then
    record "FAIL" "cloudflared: realtime ingress disabled" \
      "found route to localhost:6001 — realtime must stay on Tailscale"
  else
    record "PASS" "cloudflared: realtime ingress disabled"
  fi

  if grep -qE 'localhost:6002|127\.0\.0\.1:6002' "${config_file}"; then
    record "FAIL" "cloudflared: terminal ingress disabled" \
      "found route to localhost:6002 — terminal must stay on Tailscale"
  else
    record "PASS" "cloudflared: terminal ingress disabled"
  fi

  if grep -q '/terminal/ws' "${config_file}"; then
    record "FAIL" "cloudflared: terminal path disabled" \
      "found '/terminal/ws' ingress rule — terminal must not be publicly tunneled"
  else
    record "PASS" "cloudflared: terminal path disabled"
  fi

  local deny_count
  deny_count="$(grep -Ec 'service:\s*http_status:404' "${config_file}" || true)"
  if [[ "${deny_count}" =~ ^[0-9]+$ ]] && (( deny_count >= 2 )); then
    record "PASS" "cloudflared: deny rules present"
  else
    record "FAIL" "cloudflared: deny rules" \
      "expected at least two http_status:404 ingress rules (explicit host blocks + fallback)"
  fi

  if is_true "${TUNNEL_MODE}"; then
    local dashboard_host ws_host
    dashboard_host="$(awk '
      /^[[:space:]]*-[[:space:]]*hostname:[[:space:]]*/ {
        host=$3
        gsub(/"/, "", host)
        if (host !~ /^\*\./ && host !~ /^ws\./) {
          print host
          exit
        }
      }
    ' "${config_file}" 2>/dev/null || true)"
    ws_host="$(awk '
      /^[[:space:]]*-[[:space:]]*hostname:[[:space:]]*ws\./ {
        host=$3
        gsub(/"/, "", host)
        print host
        exit
      }
    ' "${config_file}" 2>/dev/null || true)"

    if [[ -n "${dashboard_host}" && -z "${ws_host}" ]]; then
      ws_host="ws.${dashboard_host}"
    fi

    local private_route_file
    local proxy_compose_file
    local default_redirect_file
    local coolify_dynamic_file
    local coolify_env_file
    private_route_file="${COOLIFY_PRIVATE_ROUTE_FILE:-/data/coolify/proxy/dynamic/coolify-private-dashboard.yaml}"
    proxy_compose_file="${COOLIFY_PROXY_COMPOSE_FILE:-/data/coolify/proxy/docker-compose.yml}"
    default_redirect_file="${COOLIFY_PROXY_DEFAULT_REDIRECT_FILE:-/data/coolify/proxy/dynamic/default_redirect_503.yaml}"
    coolify_dynamic_file="${COOLIFY_PROXY_DYNAMIC_FILE:-/data/coolify/proxy/dynamic/coolify.yaml}"
    coolify_env_file="${COOLIFY_ENV_FILE:-/data/coolify/source/.env}"
    if [[ -f "${private_route_file}" ]]; then
      record "PASS" "cloudflared: private dashboard route file present"
    else
      record "FAIL" "cloudflared: private dashboard route file" \
        "missing ${private_route_file}; private DOMAIN/ws routing may be broken"
    fi

    if [[ -f "${private_route_file}" && -n "${dashboard_host}" ]]; then
      if grep -Fq "Host(\`${dashboard_host}\`)" "${private_route_file}"; then
        record "PASS" "cloudflared: private dashboard host route (${dashboard_host})"
      else
        record "FAIL" "cloudflared: private dashboard host route" \
          "missing Host(\`${dashboard_host}\`) in ${private_route_file}"
      fi
    fi

    if [[ -f "${private_route_file}" && -n "${ws_host}" ]]; then
      if grep -Fq "Host(\`${ws_host}\`)" "${private_route_file}"; then
        record "PASS" "cloudflared: private websocket host route (${ws_host})"
      else
        record "FAIL" "cloudflared: private websocket host route" \
          "missing Host(\`${ws_host}\`) in ${private_route_file}"
      fi
    fi

    if [[ -f "${private_route_file}" ]]; then
      local private_router_name
      local private_router_fail=0
      for private_router_name in \
        coolify-private-dashboard-http \
        coolify-private-dashboard-https \
        coolify-private-realtime-http \
        coolify-private-realtime-https \
        coolify-private-terminal-http \
        coolify-private-terminal-https; do
        if grep -Fq "${private_router_name}:" "${private_route_file}"; then
          record "PASS" "cloudflared: private router present (${private_router_name})"
        else
          record "FAIL" "cloudflared: private router present (${private_router_name})" \
            "missing router ${private_router_name} in ${private_route_file}"
          private_router_fail=1
        fi
      done
      if [[ "${private_router_fail}" -eq 0 ]]; then
        record "PASS" "cloudflared: private http/https router set complete"
      fi

      if grep -Fq "coolify-private-force-https:" "${private_route_file}" \
        && grep -Fq "redirectScheme:" "${private_route_file}" \
        && grep -Eq '^[[:space:]]*scheme:[[:space:]]*https[[:space:]]*$' "${private_route_file}"; then
        record "PASS" "cloudflared: private HTTP→HTTPS redirect middleware"
      else
        record "FAIL" "cloudflared: private HTTP→HTTPS redirect middleware" \
          "missing coolify-private-force-https redirectScheme in ${private_route_file}"
      fi

      local http_router_name http_router_block
      for http_router_name in \
        coolify-private-dashboard-http \
        coolify-private-realtime-http \
        coolify-private-terminal-http; do
        http_router_block="$(awk -v router="${http_router_name}:" '
          $0 ~ "^    " router "[[:space:]]*$" {in_router=1; next}
          in_router && $0 ~ "^    [a-zA-Z0-9_-]+:[[:space:]]*$" {exit}
          in_router {print}
        ' "${private_route_file}")"
        if grep -Fq "service: noop@internal" <<< "${http_router_block}" \
          && grep -Fq "coolify-private-force-https" <<< "${http_router_block}"; then
          record "PASS" "cloudflared: ${http_router_name} enforces HTTPS redirect"
        else
          record "FAIL" "cloudflared: ${http_router_name} enforces HTTPS redirect" \
            "expected service noop@internal + coolify-private-force-https middleware"
        fi
      done

      local https_router_name https_router_block private_https_router_fail=0
      for https_router_name in \
        coolify-private-dashboard-https \
        coolify-private-realtime-https \
        coolify-private-terminal-https; do
        https_router_block="$(awk -v router="${https_router_name}:" '
          $0 ~ "^    " router "[[:space:]]*$" {in_router=1; next}
          in_router && $0 ~ "^    [a-zA-Z0-9_-]+:[[:space:]]*$" {exit}
          in_router {print}
        ' "${private_route_file}")"
        if grep -Eq '^[[:space:]]*certResolver:[[:space:]]*[^[:space:]]+' <<< "${https_router_block}"; then
          record "PASS" "cloudflared: ${https_router_name} uses certResolver"
        else
          record "FAIL" "cloudflared: ${https_router_name} uses certResolver" \
            "missing certResolver in ${https_router_name} router block"
          private_https_router_fail=1
        fi
      done
      if [[ "${private_https_router_fail}" -eq 0 ]]; then
        record "PASS" "cloudflared: private HTTPS routers use certResolver"
      else
        record "FAIL" "cloudflared: private HTTPS routers use certResolver" \
          "one or more private HTTPS routers in ${private_route_file} are missing certResolver"
      fi
    fi

    if [[ -f "${proxy_compose_file}" ]]; then
      if grep -Eq 'certificatesresolvers\.letsencrypt\.' "${proxy_compose_file}"; then
        record "FAIL" "cloudflared: public letsencrypt resolver removed" \
          "found public letsencrypt resolver flags in ${proxy_compose_file}"
      else
        record "PASS" "cloudflared: public letsencrypt resolver removed"
      fi

      local private_tls_resolver private_tls_ca traefik_command_block private_resolver_flag_fail
      private_tls_resolver="$(awk '
        $0 ~ /^    coolify-private-(dashboard|realtime|terminal)-https:[[:space:]]*$/ { in_router=1; next }
        in_router && /^[[:space:]]*certResolver:[[:space:]]*/ {
          gsub(/^[[:space:]]*certResolver:[[:space:]]*/, "", $0)
          print
          exit
        }
        in_router && /^    [a-zA-Z0-9_-]+:[[:space:]]*$/ { in_router=0 }
      ' "${private_route_file}" 2>/dev/null || true)"
      [[ -n "${private_tls_resolver}" ]] || private_tls_resolver="privatedns"
      private_tls_ca="letsencrypt"

      traefik_command_block="$(awk '
        /^  traefik:[[:space:]]*$/ { in_service=1; next }
        in_service && /^  [a-zA-Z0-9_-]+:[[:space:]]*$/ { exit }
        in_service && /^    command:[[:space:]]*$/ { in_command=1; next }
        in_command && /^    [a-zA-Z0-9_-]+:[[:space:]]*$/ { exit }
        in_command { print }
      ' "${proxy_compose_file}" 2>/dev/null || true)"

      private_resolver_flag_fail=0
      local required_private_resolver_flag
      for required_private_resolver_flag in \
        "--certificatesresolvers.${private_tls_resolver}.acme.dnschallenge=true" \
        "--certificatesresolvers.${private_tls_resolver}.acme.dnschallenge.provider=cloudflare" \
        "--certificatesresolvers.${private_tls_resolver}.acme.dnschallenge.resolvers=1.1.1.1:53,8.8.8.8:53" \
        "--certificatesresolvers.${private_tls_resolver}.acme.email=" \
        "--certificatesresolvers.${private_tls_resolver}.acme.storage=/traefik/acme.json"; do
        if ! grep -Fq -- "${required_private_resolver_flag}" <<< "${traefik_command_block}"; then
          private_resolver_flag_fail=1
          break
        fi
      done

      if [[ "${private_resolver_flag_fail}" -eq 0 ]]; then
        record "PASS" "cloudflared: private TLS resolver present in Traefik command"
      else
        record "FAIL" "cloudflared: private TLS resolver present in Traefik command" \
          "missing ${private_tls_resolver} ACME flags in traefik command block of ${proxy_compose_file}"
      fi

      if grep -Fq -- "--certificatesresolvers.${private_tls_resolver}.acme.caserver=https://acme.zerossl.com/v2/DV90" <<< "${traefik_command_block}"; then
        private_tls_ca="zerossl"
      fi
      if [[ "${private_tls_ca}" == "zerossl" ]]; then
        if grep -Fq -- "--certificatesresolvers.${private_tls_resolver}.acme.eab.kid=" <<< "${traefik_command_block}" \
          && grep -Fq -- "--certificatesresolvers.${private_tls_resolver}.acme.eab.hmacencoded=" <<< "${traefik_command_block}"; then
          record "PASS" "cloudflared: private TLS CA (${private_tls_ca}) flags present"
        else
          record "FAIL" "cloudflared: private TLS CA (${private_tls_ca}) flags present" \
            "missing ZeroSSL caServer/EAB flags in traefik command block of ${proxy_compose_file}"
        fi
      else
        record "PASS" "cloudflared: private TLS CA (${private_tls_ca}) flags present"
      fi
    else
      record "FAIL" "cloudflared: proxy compose file" "missing ${proxy_compose_file}"
    fi

    if [[ -f "${default_redirect_file}" ]]; then
      if grep -Eq '^[[:space:]]*certResolver:[[:space:]]*letsencrypt[[:space:]]*$' "${default_redirect_file}"; then
        record "FAIL" "cloudflared: catchall route avoids public letsencrypt" \
          "found public letsencrypt resolver in ${default_redirect_file}"
      else
        record "PASS" "cloudflared: catchall route avoids public letsencrypt"
      fi
    else
      record "PASS" "cloudflared: catchall route avoids public letsencrypt"
    fi

    if [[ -f "${coolify_dynamic_file}" ]]; then
      if grep -Eq '^[[:space:]]*coolify-(https|realtime-wss|terminal-wss):[[:space:]]*$|^[[:space:]]*certresolver:[[:space:]]*letsencrypt[[:space:]]*$' "${coolify_dynamic_file}"; then
        record "FAIL" "cloudflared: generated Coolify HTTPS routers disabled" \
          "found public dashboard HTTPS routers in ${coolify_dynamic_file}"
      else
        record "PASS" "cloudflared: generated Coolify HTTPS routers disabled"
      fi
    else
      # In tunnel mode with empty FQDN, Coolify intentionally doesn't generate this file.
      # No file = no public HTTPS routers, which is the desired state.
      record "PASS" "cloudflared: generated Coolify HTTPS routers disabled" \
        "(no ${coolify_dynamic_file} — expected when no public FQDN)"
    fi

    if [[ -n "${dashboard_host}" ]]; then
      local expected_pusher_host actual_pusher_host actual_pusher_port actual_pusher_scheme
      expected_pusher_host="ws.${dashboard_host}"
      if [[ -f "${coolify_env_file}" ]]; then
        actual_pusher_host="$(awk -F= '/^PUSHER_HOST=/{print $2; exit}' "${coolify_env_file}" | tr -d '"' || true)"
        actual_pusher_port="$(awk -F= '/^PUSHER_PORT=/{print $2; exit}' "${coolify_env_file}" | tr -d '"' || true)"
        actual_pusher_scheme="$(awk -F= '/^PUSHER_SCHEME=/{print $2; exit}' "${coolify_env_file}" | tr -d '"' || true)"

        if [[ "${actual_pusher_host}" == "${expected_pusher_host}" ]]; then
          record "PASS" "coolify: PUSHER_HOST private ws domain"
        else
          record "FAIL" "coolify: PUSHER_HOST private ws domain" \
            "expected ${expected_pusher_host}, found ${actual_pusher_host:-<unset>}"
        fi

        if [[ "${actual_pusher_port}" == "443" ]]; then
          record "PASS" "coolify: PUSHER_PORT private ws TLS"
        else
          record "FAIL" "coolify: PUSHER_PORT private ws TLS" \
            "expected 443, found ${actual_pusher_port:-<unset>}"
        fi

        if [[ "${actual_pusher_scheme}" == "https" ]]; then
          record "PASS" "coolify: PUSHER_SCHEME private ws TLS"
        else
          record "FAIL" "coolify: PUSHER_SCHEME private ws TLS" \
            "expected https, found ${actual_pusher_scheme:-<unset>}"
        fi
      else
        record "FAIL" "coolify: PUSHER env file present" \
          "missing ${coolify_env_file}"
      fi
    fi

    if command -v getent >/dev/null 2>&1; then
      check_private_dns_host() {
        local host="$1"
        local label="$2"
        local resolved_list ip
        local all_tailscale="true"
        local matched_expected="false"

        if command -v dig >/dev/null 2>&1; then
          # Query authoritative DNS directly to avoid local /etc/hosts or resolver overrides.
          resolved_list="$(dig +short @1.1.1.1 "${host}" A 2>/dev/null \
            | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/' \
            | sort -u | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
        else
          resolved_list="$(getent ahostsv4 "${host}" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
        fi
        if [[ -z "${resolved_list}" ]]; then
          record "FAIL" "cloudflared: ${label} DNS resolution" "no IPv4 answer for ${host}"
          return 0
        fi

        for ip in ${resolved_list}; do
          if ! is_tailscale_ipv4 "${ip}"; then
            all_tailscale="false"
          fi
          if [[ -n "${TAILSCALE_IP}" && "${ip}" == "${TAILSCALE_IP}" ]]; then
            matched_expected="true"
          fi
        done

        if [[ "${all_tailscale}" != "true" ]]; then
          record "FAIL" "cloudflared: ${label} DNS resolution" \
            "${host} resolved to non-Tailscale IPv4(s): ${resolved_list}"
          return 0
        fi

        if [[ -n "${TAILSCALE_IP}" && "${matched_expected}" != "true" ]]; then
          record "FAIL" "cloudflared: ${label} DNS resolution" \
            "${host} resolved to ${resolved_list}; expected to include ${TAILSCALE_IP}"
          return 0
        fi

        record "PASS" "cloudflared: ${label} DNS resolves to Tailscale (${resolved_list})"
      }

      if [[ -n "${dashboard_host}" ]]; then
        check_private_dns_host "${dashboard_host}" "dashboard host"
      else
        record "FAIL" "cloudflared: dashboard host in config" \
          "unable to parse dashboard hostname from ${config_file}"
      fi

      if [[ -n "${ws_host}" ]]; then
        check_private_dns_host "${ws_host}" "websocket host"
      else
        record "FAIL" "cloudflared: websocket host in config" \
          "unable to parse websocket hostname from ${config_file}"
      fi
    else
      record "INFO" "cloudflared: DNS resolution checks" "getent not found; skipped private DNS checks"
    fi

    check_private_tls_cert_served() {
      local host="$1"
      local label="$2"
      local cert_meta
      cert_meta="$(printf '' | openssl s_client -connect 127.0.0.1:443 -servername "${host}" -showcerts 2>/dev/null \
        | openssl x509 -noout -subject -issuer -ext subjectAltName 2>/dev/null || true)"

      if [[ -z "${cert_meta}" ]]; then
        record "FAIL" "cloudflared: ${label} served TLS cert" \
          "could not inspect served certificate for ${host} on 127.0.0.1:443"
        return 0
      fi

      if grep -Fq "TRAEFIK DEFAULT CERT" <<< "${cert_meta}"; then
        record "FAIL" "cloudflared: ${label} served TLS cert" \
          "Traefik default certificate still served for ${host}"
      else
        record "PASS" "cloudflared: ${label} served TLS cert"
      fi

      if grep -Fq "DNS:${host}" <<< "${cert_meta}"; then
        record "PASS" "cloudflared: ${label} certificate SAN (${host})"
      else
        record "FAIL" "cloudflared: ${label} certificate SAN (${host})" \
          "missing DNS:${host} in served certificate"
      fi
    }

    if command -v openssl >/dev/null 2>&1; then
      if [[ -n "${dashboard_host}" ]]; then
        check_private_tls_cert_served "${dashboard_host}" "dashboard host"
      fi
      if [[ -n "${ws_host}" ]]; then
        check_private_tls_cert_served "${ws_host}" "websocket host"
      fi
    else
      record "INFO" "cloudflared: private TLS certificate checks" "openssl not found; skipped served certificate checks"
    fi

    if command -v curl >/dev/null 2>&1; then
      if [[ -n "${dashboard_host}" ]]; then
        local private_dashboard_http_code
        private_dashboard_http_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
          --resolve "${dashboard_host}:80:127.0.0.1" "http://${dashboard_host}" 2>/dev/null || true)"
        private_dashboard_http_code="${private_dashboard_http_code:-000}"
        private_dashboard_http_code="${private_dashboard_http_code:0:3}"

        if [[ "${private_dashboard_http_code}" =~ ^30[12378]$ ]]; then
          record "PASS" "cloudflared: private dashboard HTTP redirect verified"
        else
          record "FAIL" "cloudflared: private dashboard HTTP redirect verified" \
            "expected 30x from http://${dashboard_host} via local Traefik, got ${private_dashboard_http_code}"
        fi

        local private_dashboard_https_code
        private_dashboard_https_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
          --resolve "${dashboard_host}:443:127.0.0.1" "https://${dashboard_host}/api/v1/health" 2>/dev/null || true)"
        private_dashboard_https_code="${private_dashboard_https_code:-000}"
        private_dashboard_https_code="${private_dashboard_https_code:0:3}"

        if [[ "${private_dashboard_https_code}" =~ ^2[0-9][0-9]$ ]]; then
          record "PASS" "cloudflared: private dashboard HTTPS health verified"
        else
          record "FAIL" "cloudflared: private dashboard HTTPS health verified" \
            "expected 2xx from https://${dashboard_host}/api/v1/health via local Traefik, got ${private_dashboard_https_code}"
        fi
      fi

      if [[ -n "${ws_host}" ]]; then
        local private_ws_http_code private_ws_https_code
        private_ws_http_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
          --resolve "${ws_host}:80:127.0.0.1" "http://${ws_host}" 2>/dev/null || true)"
        private_ws_https_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
          --resolve "${ws_host}:443:127.0.0.1" "https://${ws_host}/" 2>/dev/null || true)"
        private_ws_http_code="${private_ws_http_code:-000}"
        private_ws_https_code="${private_ws_https_code:-000}"
        private_ws_http_code="${private_ws_http_code:0:3}"
        private_ws_https_code="${private_ws_https_code:0:3}"

        if [[ "${private_ws_http_code}" =~ ^30[12378]$ ]]; then
          record "PASS" "cloudflared: private websocket HTTP redirect verified"
        else
          record "FAIL" "cloudflared: private websocket HTTP redirect verified" \
            "expected 30x from http://${ws_host} via local Traefik, got ${private_ws_http_code}"
        fi

        if [[ "${private_ws_https_code}" =~ ^[234][0-9][0-9]$ ]]; then
          record "PASS" "cloudflared: private websocket HTTPS route verified"
        else
          record "FAIL" "cloudflared: private websocket HTTPS route verified" \
            "expected 2xx/3xx/4xx from https://${ws_host}/ via local Traefik, got ${private_ws_https_code}"
        fi
      fi
    else
      record "INFO" "cloudflared: private dashboard HTTP redirect verified" "curl not found; skipped redirect check"
      record "INFO" "cloudflared: private dashboard HTTPS health verified" "curl not found; skipped verified HTTPS health check"
      record "INFO" "cloudflared: private websocket HTTP redirect verified" "curl not found; skipped redirect check"
      record "INFO" "cloudflared: private websocket HTTPS route verified" "curl not found; skipped verified HTTPS route check"
    fi
  fi

  # Functional connectivity: probe cloudflared's /ready endpoint.
  # The metrics port is not always 2000; newer cloudflared picks an ephemeral port or
  # uses a management socket. Discover the port dynamically from ss/procfs, then probe it.
  local cf_pid cf_port
  cf_pid="$(pgrep -x cloudflared | head -1 || true)"
  if [[ -n "${cf_pid}" ]]; then
    cf_port="$(ss -tlnp 2>/dev/null \
      | awk -v pid="${cf_pid}" 'index($0,"pid="pid",") && /127\.0\.0\.1:/{print $4}' \
      | awk -F: '{print $NF}' | head -1 || true)"
  fi

  if [[ -n "${cf_port:-}" ]] && curl -sf --max-time 3 "http://127.0.0.1:${cf_port}/ready" >/dev/null 2>&1; then
    local ready_json conn_count
    ready_json="$(curl -sf --max-time 3 "http://127.0.0.1:${cf_port}/ready" 2>/dev/null || true)"
    conn_count="$(printf '%s' "${ready_json}" | python3 -c \
      "import sys,json; print(json.load(sys.stdin).get('readyConnections',0))" 2>/dev/null || echo "?")"
    record "PASS" "cloudflared: tunnel /ready OK (${conn_count} connections)"
  elif [[ -n "${cf_port:-}" ]]; then
    record "FAIL" "cloudflared: tunnel /ready" \
      "port ${cf_port} not responding — tunnel may be disconnected"
  else
    record "INFO" "cloudflared: tunnel /ready" \
      "could not determine cloudflared metrics port — manual check needed"
  fi
}

# ── Coolify container health ──
# Gate-C safe: skips entirely if /data/coolify does not exist.

coolify_container_check() {
  if ! command -v docker >/dev/null 2>&1; then
    record "INFO" "coolify-containers: docker" "Docker not installed; skipped"
    return
  fi

  # Gate-C safe: only enforce Coolify container health after Coolify environment
  # has been created. Partial directories from interrupted installs should not
  # fail pre-phase3 validation.
  if [[ ! -f "${COOLIFY_ENV_FILE}" ]]; then
    return 0
  fi

  local containers=("coolify" "coolify-db" "coolify-redis" "coolify-proxy")
  for ctr in "${containers[@]}"; do
    local state health
    state="$(docker inspect --format '{{.State.Status}}' "${ctr}" 2>/dev/null || echo "not-found")"
    state="$(printf '%s' "${state}" | tr -d '[:space:]')"
    if [[ "${state}" == "not-found" ]]; then
      # proxy may genuinely be absent if no apps deployed yet — info not fail
      if [[ "${ctr}" == "coolify-proxy" ]]; then
        record "INFO" "coolify-containers: ${ctr}" "not found (normal before first app deploy)"
      else
        record "FAIL" "coolify-containers: ${ctr}" "container not found"
      fi
      continue
    fi

    if [[ "${state}" != "running" ]]; then
      record "FAIL" "coolify-containers: ${ctr} running" "state is ${state}"
      continue
    fi

    # Check healthcheck status if configured (some containers have none)
    health="$(docker inspect \
      --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}' \
      "${ctr}" 2>/dev/null || echo "unknown")"
    health="$(printf '%s' "${health}" | tr -d '[:space:]')"

    case "${health}" in
      healthy|no-healthcheck)
        record "PASS" "coolify-containers: ${ctr} running (${health})" ;;
      starting)
        record "INFO" "coolify-containers: ${ctr}" "healthcheck still starting — re-run in a minute" ;;
      *)
        record "FAIL" "coolify-containers: ${ctr} health" "${health}" ;;
    esac
  done
}

coolify_instance_settings_check() {
  if ! command -v docker >/dev/null 2>&1; then
    record "INFO" "coolify: instance settings" "Docker not installed; skipped"
    return
  fi

  if [[ ! -f "${COOLIFY_ENV_FILE}" ]]; then
    return 0
  fi

  if [[ -z "${DOMAIN}" ]]; then
    record "FAIL" "coolify: instance fqdn" "domain missing from ${STATE_FILE}"
    record "FAIL" "coolify: registration disabled" "domain missing from ${STATE_FILE}"
    return
  fi

  local db_user db_name db_pass settings_row registration_enabled fqdn expected_fqdn
  db_user="$(grep -m1 '^DB_USERNAME=' "${COOLIFY_ENV_FILE}" | cut -d= -f2- || true)"
  db_name="$(grep -m1 '^DB_DATABASE=' "${COOLIFY_ENV_FILE}" | cut -d= -f2- || true)"
  db_pass="$(grep -m1 '^DB_PASSWORD=' "${COOLIFY_ENV_FILE}" | cut -d= -f2- || true)"
  db_user="${db_user:-coolify}"
  db_name="${db_name:-coolify}"
  if is_true "${TUNNEL_MODE}"; then
    expected_fqdn=""
  else
    expected_fqdn="https://${DOMAIN}"
  fi

  if [[ -z "${db_pass}" ]]; then
    record "FAIL" "coolify: instance settings query" "DB_PASSWORD missing in ${COOLIFY_ENV_FILE}"
    return
  fi

  if ! docker ps --filter "name=coolify-db" --filter "status=running" --format "{{.Names}}" 2>/dev/null | grep -qx "coolify-db"; then
    record "FAIL" "coolify: instance settings query" "coolify-db container is not running"
    return
  fi

  local pg_ready="false" attempt
  for (( attempt=1; attempt<=15; attempt++ )); do
    if docker exec -i coolify-db sh -ceu '
      IFS= read -r PGPASSWORD
      export PGPASSWORD
      pg_isready -U "$1" -d "$2" >/dev/null 2>&1
    ' _ "${db_user}" "${db_name}" <<< "${db_pass}" >/dev/null 2>&1; then
      pg_ready="true"
      break
    fi
    (( attempt < 15 )) || break
    sleep 2
  done

  if [[ "${pg_ready}" != "true" ]]; then
    record "FAIL" "coolify: instance settings query" "coolify-db is running but PostgreSQL is not ready"
    return
  fi

  settings_row="$(
    docker exec -i coolify-db env PGPASSWORD="${db_pass}" \
      psql -v ON_ERROR_STOP=1 -U "${db_user}" -d "${db_name}" -At -F '|' \
      -c "SELECT is_registration_enabled, COALESCE(fqdn,'') FROM instance_settings LIMIT 1;" \
      2>/dev/null || true
  )"

  if [[ -z "${settings_row}" ]]; then
    record "FAIL" "coolify: instance settings query" "instance_settings query returned no data"
    return
  fi

  registration_enabled="${settings_row%%|*}"
  fqdn="${settings_row#*|}"

  if [[ "${registration_enabled}" == "f" || "${registration_enabled}" == "false" ]]; then
    record "PASS" "coolify: registration disabled"
  else
    record "FAIL" "coolify: registration disabled" \
      "expected false, found ${registration_enabled:-<empty>}"
  fi

  if [[ "${fqdn}" == "${expected_fqdn}" ]]; then
    record "PASS" "coolify: instance fqdn"
  else
    record "FAIL" "coolify: instance fqdn" \
      "expected ${expected_fqdn:-<empty>}, found ${fqdn:-<empty>}"
  fi
}

# ── Hardening validation timer ──

validate_timer_check() {
  if systemctl is-active --quiet hardening-validate.timer 2>/dev/null; then
    record "PASS" "validate-timer: active"
  elif systemctl list-unit-files --no-legend hardening-validate.timer 2>/dev/null | grep -q hardening-validate; then
    record "FAIL" "validate-timer: active" "timer installed but not active"
  else
    record "INFO" "validate-timer: not installed" "run bootstrap to install"
  fi
}

# ── Run all checks ──

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
